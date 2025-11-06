// metrics/metrics_collector.cpp
//
// Enhanced metrics collector for ns-3 simulations (ns-3.46).
// Tracks per-node and global:
//  - packets_sent, packets_received
//  - bytes_sent, bytes_received
//  - packet delivery ratio (computed on summary)
//  - throughput (bytes / second over measured interval)
//  - end-to-end delay (requires sender to pass original send time)
//  - energy: reads BasicEnergySource remaining energy if attached to node
//  - computational overhead: accumulate crypto CPU time (microseconds) and per-op breakdown
//  - CSV export for automated analysis
//
// Usage: same as before. New methods:
//   AddCryptoOp(nodeIndex, "ECDH", usec)   // record named op time
//   WriteSummaryCsv(path)
//   WriteNodeDetailsCsv(path)

#include <ns3/core-module.h>
#include <ns3/network-module.h>
#include <ns3/energy-module.h>
#include <ns3/internet-module.h>

#include <unordered_map>
#include <vector>
#include <mutex>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <map>
#include <sstream>

using namespace ns3;

namespace metrics {

struct NodeMetrics {
    uint64_t packets_sent = 0;
    uint64_t packets_received = 0;
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    // delay stats (sum and count) in seconds (double)
    double sum_delay_s = 0.0;
    uint64_t delay_count = 0;
    // crypto CPU time accumulated (microseconds)
    uint64_t crypto_us = 0;

    // per-op crypto breakdown (op name -> microseconds)
    std::map<std::string, uint64_t> crypto_ops_us;

    // energy: captured at registration (initial) and at summary (remaining)
    double initial_energy_j = 0.0;
    double final_energy_j = 0.0;

    void AddSend(uint64_t bytes) {
        packets_sent++;
        bytes_sent += bytes;
    }
    void AddRecv(uint64_t bytes, double delay_s) {
        packets_received++;
        bytes_received += bytes;
        sum_delay_s += delay_s;
        delay_count++;
    }
    void AddCryptoTimeUs(uint64_t us) {
        crypto_us += us;
    }
    void AddCryptoOp(const std::string &op, uint64_t us) {
        crypto_ops_us[op] += us;
        crypto_us += us;
    }
    double AvgDelay() const {
        if (delay_count == 0) return 0.0;
        return sum_delay_s / static_cast<double>(delay_count);
    }
};

class MetricsCollector {
public:
    MetricsCollector() = default;

    // Register a node (optional) so we can read its energy source snapshot.
    // nodeIndex is your simulation's node index (0..N-1).
    // If the node has a BasicEnergySource installed, its energy will be read at registration.
    void RegisterNode(uint32_t nodeIndex, Ptr<Node> node) {
        std::lock_guard<std::mutex> lk(mu_);
        nodes_[nodeIndex]; // ensure entry exists
        nodePtrs_[nodeIndex] = node;
        // capture initial energy if BasicEnergySource present
        Ptr<ns3::energy::BasicEnergySource> bes = GetBasicEnergySource(node);
        if (bes) {
            nodes_[nodeIndex].initial_energy_j = bes->GetRemainingEnergy();
        } else {
            nodes_[nodeIndex].initial_energy_j = 0.0;
        }
    }

    // Called when your application sends a packet (at sender).
    void OnPacketSent(uint32_t nodeIndex, uint64_t bytes) {
        std::lock_guard<std::mutex> lk(mu_);
        nodes_[nodeIndex].AddSend(bytes);
        if (first_send_time_.IsZero()) {
            first_send_time_ = Simulator::Now();
        }
        last_activity_time_ = Simulator::Now();
    }

    // Called when your application receives a packet.
    // sendTime: the original sender timestamp in simulator Seconds (double) or 0 if unavailable.
    void OnPacketReceived(uint32_t nodeIndex, uint64_t bytes, double sendTimeSeconds) {
        std::lock_guard<std::mutex> lk(mu_);
        double now_s = Simulator::Now().GetSeconds();
        double delay_s = 0.0;
        if (sendTimeSeconds > 0.0) {
            delay_s = now_s - sendTimeSeconds;
            if (delay_s < 0.0) delay_s = 0.0;
        }
        nodes_[nodeIndex].AddRecv(bytes, delay_s);
        if (first_send_time_.IsZero()) {
            first_send_time_ = Simulator::Now();
        }
        last_activity_time_ = Simulator::Now();
    }

    // Add measured crypto CPU time for a node (in microseconds)
    void AddCryptoTimeUs(uint32_t nodeIndex, uint64_t usec) {
        std::lock_guard<std::mutex> lk(mu_);
        nodes_[nodeIndex].AddCryptoTimeUs(usec);
    }

    // Record a named crypto operation for breakdown, e.g., "ECDH", "SIGN", "AEAD"
    void AddCryptoOp(uint32_t nodeIndex, const std::string &opName, uint64_t usec) {
        std::lock_guard<std::mutex> lk(mu_);
        nodes_[nodeIndex].AddCryptoOp(opName, usec);
    }

    // Capture final energy states for all registered nodes (call near simulation end)
    void CaptureFinalEnergyStates() {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto &p : nodePtrs_) {
            uint32_t idx = p.first;
            Ptr<Node> node = p.second;
            Ptr<ns3::energy::BasicEnergySource> bes = GetBasicEnergySource(node);
            if (bes) {
                nodes_[idx].final_energy_j = bes->GetRemainingEnergy();
            } else {
                nodes_[idx].final_energy_j = 0.0;
            }
        }
    }

    // Print a human-readable summary to stdout
    void PrintSummary(std::ostream &os = std::cout) {
        std::lock_guard<std::mutex> lk(mu_);
        CaptureFinalEnergyStates();

        os << "\n=== Metrics Summary ===\n";
        os << "Simulation time: ";
        if (first_send_time_.IsZero()) {
            os << "0s (no activity)\n";
        } else {
            Time sim_now = Simulator::Now();
            os << sim_now.GetSeconds() << " s\n";
        }

        uint64_t total_sent = 0, total_recv = 0;
        uint64_t total_bytes_sent = 0, total_bytes_recv = 0;
        double total_delay_sum = 0.0;
        uint64_t total_delay_count = 0;
        uint64_t total_crypto_us = 0;
        double total_initial_energy = 0.0;
        double total_final_energy = 0.0;

        os << std::left << std::setw(8) << "Node"
           << std::setw(10) << "PktsSent"
           << std::setw(10) << "PktsRecv"
           << std::setw(12) << "BytesSent"
           << std::setw(12) << "BytesRecv"
           << std::setw(12) << "AvgDelay(s)"
           << std::setw(12) << "Crypto(ms)"
           << std::setw(12) << "InitE(J)"
           << std::setw(12) << "FinalE(J)"
           << "\n";

        for (auto &entry : nodes_) {
            uint32_t idx = entry.first;
            const NodeMetrics &m = entry.second;
            os << std::setw(8) << idx
               << std::setw(10) << m.packets_sent
               << std::setw(10) << m.packets_received
               << std::setw(12) << m.bytes_sent
               << std::setw(12) << m.bytes_received
               << std::setw(12) << std::fixed << std::setprecision(4) << m.AvgDelay()
               << std::setw(12) << (m.crypto_us / 1000.0) // ms
               << std::setw(12) << std::fixed << std::setprecision(3) << m.initial_energy_j
               << std::setw(12) << std::fixed << std::setprecision(3) << m.final_energy_j
               << "\n";

            total_sent += m.packets_sent;
            total_recv += m.packets_received;
            total_bytes_sent += m.bytes_sent;
            total_bytes_recv += m.bytes_received;
            total_delay_sum += m.sum_delay_s;
            total_delay_count += m.delay_count;
            total_crypto_us += m.crypto_us;
            total_initial_energy += m.initial_energy_j;
            total_final_energy += m.final_energy_j;
        }

        double overall_avg_delay = (total_delay_count == 0) ? 0.0 : (total_delay_sum / static_cast<double>(total_delay_count));
        double runtime_s = Simulator::Now().GetSeconds();
        double throughput_bps = (runtime_s > 0.0) ? (static_cast<double>(total_bytes_recv) * 8.0 / runtime_s) : 0.0;
        double pdr = (total_sent == 0) ? 0.0 : (static_cast<double>(total_recv) / static_cast<double>(total_sent));

        os << "\n--- Global ---\n";
        os << "Total packets sent: " << total_sent << "\n";
        os << "Total packets recv: " << total_recv << "\n";
        os << "Packet Delivery Ratio (PDR): " << std::fixed << std::setprecision(4) << pdr << "\n";
        os << "Throughput (recv, bits/s): " << std::fixed << std::setprecision(2) << throughput_bps << "\n";
        os << "Avg end-to-end delay (s): " << overall_avg_delay << "\n";
        os << "Total crypto CPU time (ms): " << (total_crypto_us / 1000.0) << "\n";
        os << "Total initial energy (J): " << total_initial_energy << "\n";
        os << "Total final energy (J): " << total_final_energy << "\n";
        os << "Total energy consumed (J): " << (total_initial_energy - total_final_energy) << "\n";
        os << "======================\n\n";
    }

    // Write a CSV with per-node rows + a final global summary row
    // Columns: node,pkts_sent,pkts_recv,bytes_sent,bytes_recv,avg_delay_s,crypto_ms,initE_j,finalE_j,pdr,throughput_bps
    bool WriteSummaryCsv(const std::string &path) {
        std::lock_guard<std::mutex> lk(mu_);
        CaptureFinalEnergyStates();
        std::ofstream f(path);
        if (!f.is_open()) return false;

        f << "node,pkts_sent,pkts_recv,bytes_sent,bytes_recv,avg_delay_s,crypto_ms,initE_j,finalE_j,pdr,throughput_bps\n";

        uint64_t total_sent = 0, total_recv = 0, total_bytes_recv = 0;
        double total_delay_sum = 0.0;
        uint64_t total_delay_count = 0;
        uint64_t total_crypto_us = 0;
        double total_initial_energy = 0.0;
        double total_final_energy = 0.0;

        double runtime_s = Simulator::Now().GetSeconds();

        for (auto &entry : nodes_) {
            uint32_t idx = entry.first;
            const NodeMetrics &m = entry.second;
            double avg_delay = m.AvgDelay();
            double crypto_ms = m.crypto_us / 1000.0;
            double pdr_node = (m.packets_sent == 0) ? 0.0 : (static_cast<double>(m.packets_received) / static_cast<double>(m.packets_sent));
            double throughput_bps_node = (runtime_s > 0.0) ? (static_cast<double>(m.bytes_received) * 8.0 / runtime_s) : 0.0;

            f << idx << ","
              << m.packets_sent << ","
              << m.packets_received << ","
              << m.bytes_sent << ","
              << m.bytes_received << ","
              << avg_delay << ","
              << crypto_ms << ","
              << m.initial_energy_j << ","
              << m.final_energy_j << ","
              << pdr_node << ","
              << throughput_bps_node << "\n";

            total_sent += m.packets_sent;
            total_recv += m.packets_received;
            total_bytes_recv += m.bytes_received;
            total_delay_sum += m.sum_delay_s;
            total_delay_count += m.delay_count;
            total_crypto_us += m.crypto_us;
            total_initial_energy += m.initial_energy_j;
            total_final_energy += m.final_energy_j;
        }

        double overall_avg_delay = (total_delay_count == 0) ? 0.0 : (total_delay_sum / static_cast<double>(total_delay_count));
        double overall_throughput_bps = (runtime_s > 0.0) ? (static_cast<double>(total_bytes_recv) * 8.0 / runtime_s) : 0.0;
        double overall_pdr = (total_sent == 0) ? 0.0 : (static_cast<double>(total_recv) / static_cast<double>(total_sent));
        double total_crypto_ms = total_crypto_us / 1000.0;

        // final summary row (node = ALL)
        f << "ALL,"
          << total_sent << ","
          << total_recv << ","
          << " ,"
          << total_bytes_recv << ","
          << overall_avg_delay << ","
          << total_crypto_ms << ","
          << total_initial_energy << ","
          << total_final_energy << ","
          << overall_pdr << ","
          << overall_throughput_bps << "\n";

        f.close();
        return true;
    }

    // Write a CSV with per-node detailed metrics including per-op crypto breakdown serialized as semi-colon separated op:us pairs
    // Columns: node,pkts_sent,pkts_recv,bytes_sent,bytes_recv,avg_delay_s,crypto_ms,crypto_ops,initE_j,finalE_j
    bool WriteNodeDetailsCsv(const std::string &path) {
        std::lock_guard<std::mutex> lk(mu_);
        CaptureFinalEnergyStates();
        std::ofstream f(path);
        if (!f.is_open()) return false;

        f << "node,pkts_sent,pkts_recv,bytes_sent,bytes_recv,avg_delay_s,crypto_ms,crypto_ops,initE_j,finalE_j\n";
        for (auto &entry : nodes_) {
            uint32_t idx = entry.first;
            const NodeMetrics &m = entry.second;
            double avg_delay = m.AvgDelay();
            double crypto_ms = m.crypto_us / 1000.0;

            // prepare crypto_ops string "op1:us;op2:us"
            std::stringstream ops;
            bool first = true;
            for (auto &op : m.crypto_ops_us) {
                if (!first) ops << ";";
                ops << op.first << ":" << op.second;
                first = false;
            }

            f << idx << ","
              << m.packets_sent << ","
              << m.packets_received << ","
              << m.bytes_sent << ","
              << m.bytes_received << ","
              << avg_delay << ","
              << crypto_ms << ","
              << "\"" << ops.str() << "\"" << ","
              << m.initial_energy_j << ","
              << m.final_energy_j << "\n";
        }

        f.close();
        return true;
    }

private:
    std::unordered_map<uint32_t, NodeMetrics> nodes_;
    std::unordered_map<uint32_t, Ptr<Node>> nodePtrs_;
    Time first_send_time_ = Seconds(0);
    Time last_activity_time_ = Seconds(0);
    std::mutex mu_;

    // Helper: find BasicEnergySource attached to node (returns nullptr if none)
    Ptr<ns3::energy::BasicEnergySource> GetBasicEnergySource(Ptr<Node> node) {
        if (!node) return nullptr;
        // ns-3.46: templated GetObject
        return node->GetObject<ns3::energy::BasicEnergySource>();
    }
};

} // namespace metrics

// Note: keep the factory alias for compatibility
// Example usage (from main simulation):
//   auto collector = std::make_shared<metrics::MetricsCollector>();
//   collector->RegisterNode(i, nodePtr);
//   collector->OnPacketSent(i, bytes);
//   collector->OnPacketReceived(j, bytes, sendTimeSeconds);
//   collector->AddCryptoOp(nodeIdx, "ECDH", usec);
//   Simulator::Run();
//   collector->PrintSummary();
//   collector->WriteSummaryCsv("build/metrics_summary.csv");
//   collector->WriteNodeDetailsCsv("build/metrics_node_details.csv");
