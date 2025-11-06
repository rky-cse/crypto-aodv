// metrics/metrics_collector.cpp
//
// Simple metrics collector for ns-3 simulations.
// Tracks per-node and global stats and writes CSV outputs.
//
// Fixed: removed nested-lock deadlock (CaptureFinalEnergyStates no longer locks).
// Added missing includes and simplified debug output.

#include <ns3/core-module.h>
#include <ns3/network-module.h>
#include <ns3/energy-module.h>
#include <ns3/internet-module.h>

#include <unordered_map>
#include <map>
#include <vector>
#include <mutex>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include <filesystem>
#include <cerrno>
#include <cstring>
#include <unistd.h> // for getcwd

using namespace ns3;

namespace metrics {

struct NodeMetrics {
    uint64_t packets_sent = 0;
    uint64_t packets_received = 0;
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    double sum_delay_s = 0.0;
    uint64_t delay_count = 0;
    uint64_t crypto_us = 0;
    double initial_energy_j = 0.0;
    double final_energy_j = 0.0;

    void AddSend(uint64_t bytes) {
        ++packets_sent;
        bytes_sent += bytes;
    }
    void AddRecv(uint64_t bytes, double delay_s) {
        ++packets_received;
        bytes_received += bytes;
        sum_delay_s += delay_s;
        ++delay_count;
    }
    void AddCryptoTimeUs(uint64_t us) {
        crypto_us += us;
    }
    double AvgDelay() const {
        return (delay_count == 0) ? 0.0 : (sum_delay_s / static_cast<double>(delay_count));
    }
};

struct CryptoOpStats {
    uint64_t count = 0;
    uint64_t total_us = 0;
    void Add(uint64_t us) { ++count; total_us += us; }
};

class MetricsCollector {
public:
    MetricsCollector() = default;

    void RegisterNode(uint32_t nodeIndex, Ptr<Node> node) {
        std::lock_guard<std::mutex> lk(mu_);
        nodes_[nodeIndex]; // ensure entry exists
        nodePtrs_[nodeIndex] = node;
        // capture initial energy if BasicEnergySource present
        Ptr<ns3::energy::BasicEnergySource> bes = GetBasicEnergySource(node);
        nodes_[nodeIndex].initial_energy_j = (bes ? bes->GetRemainingEnergy() : 0.0);
    }

    void OnPacketSent(uint32_t nodeIndex, uint64_t bytes) {
        std::lock_guard<std::mutex> lk(mu_);
        nodes_[nodeIndex].AddSend(bytes);
        if (first_send_time_.IsZero()) first_send_time_ = Simulator::Now();
        last_activity_time_ = Simulator::Now();
    }

    void OnPacketReceived(uint32_t nodeIndex, uint64_t bytes, double sendTimeSeconds) {
        std::lock_guard<std::mutex> lk(mu_);
        double now_s = Simulator::Now().GetSeconds();
        double delay_s = 0.0;
        if (sendTimeSeconds > 0.0) {
            delay_s = now_s - sendTimeSeconds;
            if (delay_s < 0.0) delay_s = 0.0;
        }
        nodes_[nodeIndex].AddRecv(bytes, delay_s);
        if (first_send_time_.IsZero()) first_send_time_ = Simulator::Now();
        last_activity_time_ = Simulator::Now();
    }

    void AddCryptoTimeUs(uint32_t nodeIndex, uint64_t usec) {
        std::lock_guard<std::mutex> lk(mu_);
        nodes_[nodeIndex].AddCryptoTimeUs(usec);
    }

    void AddCryptoOp(uint32_t nodeIndex, const std::string &opName, uint64_t usec) {
        std::lock_guard<std::mutex> lk(mu_);
        crypto_ops_[nodeIndex][opName].Add(usec);
    }

    // Public wrapper: capture final energies (locks internally)
    void CaptureFinalEnergyStatesPublic() {
        std::lock_guard<std::mutex> lk(mu_);
        CaptureFinalEnergyStatesUnlocked();
    }

    // Print human-readable summary (locks internally)
    void PrintSummary(std::ostream &os = std::cout) {
        std::lock_guard<std::mutex> lk(mu_);
        // capture final energy while holding lock (no nested lock)
        CaptureFinalEnergyStatesUnlocked();

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
           << std::setw(12) << "PktsSent"
           << std::setw(14) << "PktsRecv"
           << std::setw(14) << "BytesSent"
           << std::setw(14) << "BytesRecv"
           << std::setw(12) << "AvgDelay(s)"
           << std::setw(14) << "Crypto(ms)"
           << std::setw(14) << "InitE(J)"
           << std::setw(14) << "FinalE(J)"
           << "\n";

        for (const auto &entry : nodes_) {
            uint32_t idx = entry.first;
            const NodeMetrics &m = entry.second;
            os << std::setw(8) << idx
               << std::setw(12) << m.packets_sent
               << std::setw(14) << m.packets_received
               << std::setw(14) << m.bytes_sent
               << std::setw(14) << m.bytes_received
               << std::setw(12) << std::fixed << std::setprecision(4) << m.AvgDelay()
               << std::setw(14) << (m.crypto_us / 1000.0)
               << std::setw(14) << m.initial_energy_j
               << std::setw(14) << m.final_energy_j
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

        os << "\n--- Crypto Ops (per-node) ---\n";
        for (const auto &nodeEntry : crypto_ops_) {
            uint32_t idx = nodeEntry.first;
            os << "Node " << idx << ":\n";
            for (const auto &opEntry : nodeEntry.second) {
                const std::string &op = opEntry.first;
                const CryptoOpStats &s = opEntry.second;
                os << "  " << op << " -> count=" << s.count << " total_ms=" << (s.total_us / 1000.0) << "\n";
            }
        }
        os << "======================\n\n";
    }

    bool WriteSummaryCsv(const std::string &path) {
        std::lock_guard<std::mutex> lk(mu_);
        // capture final energy while locked
        CaptureFinalEnergyStatesUnlocked();

        // debug: cwd + abs
        char *cwd = getcwd(nullptr, 0);
        if (cwd) { std::cerr << "[DEBUG] WriteSummaryCsv: cwd = " << cwd << "\n"; free(cwd); }
        try {
            std::filesystem::path ap = std::filesystem::absolute(path);
            std::cerr << "[DEBUG] WriteSummaryCsv: absolute = '" << ap.string() << "'\n";
        } catch (...) { /* ignore */ }

        // ensure parent exists
        try {
            std::filesystem::path p(path);
            if (p.has_parent_path()) std::filesystem::create_directories(p.parent_path());
        } catch (const std::exception &e) {
            std::cerr << "[DEBUG] WriteSummaryCsv: create_directories failed: " << e.what() << "\n";
        }

        std::ofstream fout(path, std::ios::out | std::ios::trunc);
        if (!fout.is_open()) {
            int e = errno;
            std::cerr << "[DEBUG] WriteSummaryCsv: failed to open '" << path << "'; errno=" << e
                      << " (" << (e ? std::strerror(e) : "0") << ")\n";
            return false;
        }
        std::cerr << "[DEBUG] WriteSummaryCsv: opened '" << path << "'\n";

        fout << "Node,PktsSent,PktsRecv,BytesSent,BytesRecv,AvgDelay_s,Crypto_ms,InitE_J,FinalE_J\n";
        uint64_t total_sent = 0, total_recv = 0;
        uint64_t total_bytes_sent = 0, total_bytes_recv = 0;
        double total_delay_sum = 0.0;
        uint64_t total_delay_count = 0;
        uint64_t total_crypto_us = 0;
        double total_init_e = 0.0, total_final_e = 0.0;

        for (const auto &entry : nodes_) {
            uint32_t idx = entry.first;
            const NodeMetrics &m = entry.second;
            fout << idx << ","
                 << m.packets_sent << ","
                 << m.packets_received << ","
                 << m.bytes_sent << ","
                 << m.bytes_received << ","
                 << std::fixed << std::setprecision(6) << m.AvgDelay() << ","
                 << (m.crypto_us / 1000.0) << ","
                 << m.initial_energy_j << ","
                 << m.final_energy_j << "\n";

            total_sent += m.packets_sent;
            total_recv += m.packets_received;
            total_bytes_sent += m.bytes_sent;
            total_bytes_recv += m.bytes_received;
            total_delay_sum += m.sum_delay_s;
            total_delay_count += m.delay_count;
            total_crypto_us += m.crypto_us;
            total_init_e += m.initial_energy_j;
            total_final_e += m.final_energy_j;
        }

        double overall_avg_delay = (total_delay_count == 0) ? 0.0 : (total_delay_sum / static_cast<double>(total_delay_count));
        fout << "ALL" << ","
             << total_sent << ","
             << total_recv << ","
             << total_bytes_sent << ","
             << total_bytes_recv << ","
             << std::fixed << std::setprecision(6) << overall_avg_delay << ","
             << (total_crypto_us / 1000.0) << ","
             << total_init_e << ","
             << total_final_e << "\n";

        fout.close();
        std::cerr << "[DEBUG] WriteSummaryCsv: wrote & closed '" << path << "'\n";
        return true;
    }

    bool WriteNodeDetailsCsv(const std::string &path) {
        std::lock_guard<std::mutex> lk(mu_);

        // debug: cwd + abs
        char *cwd = getcwd(nullptr, 0);
        if (cwd) { std::cerr << "[DEBUG] WriteNodeDetailsCsv: cwd = " << cwd << "\n"; free(cwd); }
        try {
            std::filesystem::path ap = std::filesystem::absolute(path);
            std::cerr << "[DEBUG] WriteNodeDetailsCsv: absolute = '" << ap.string() << "'\n";
        } catch (...) { /* ignore */ }

        try {
            std::filesystem::path p(path);
            if (p.has_parent_path()) std::filesystem::create_directories(p.parent_path());
        } catch (const std::exception &e) {
            std::cerr << "[DEBUG] WriteNodeDetailsCsv: create_directories failed: " << e.what() << "\n";
        }

        std::ofstream fout(path, std::ios::out | std::ios::trunc);
        if (!fout.is_open()) {
            int e = errno;
            std::cerr << "[DEBUG] WriteNodeDetailsCsv: failed to open '" << path << "'; errno=" << e
                      << " (" << (e ? std::strerror(e) : "0") << ")\n";
            return false;
        }
        std::cerr << "[DEBUG] WriteNodeDetailsCsv: opened '" << path << "'\n";

        fout << "Node,OpName,Count,Total_us,Total_ms\n";
        for (const auto &nodeEntry : crypto_ops_) {
            uint32_t idx = nodeEntry.first;
            for (const auto &opEntry : nodeEntry.second) {
                const std::string &op = opEntry.first;
                const CryptoOpStats &s = opEntry.second;
                fout << idx << ",\"" << EscapeCsv(op) << "\"," << s.count << "," << s.total_us << "," << (s.total_us / 1000.0) << "\n";
            }
        }
        fout.close();
        std::cerr << "[DEBUG] WriteNodeDetailsCsv: wrote & closed '" << path << "'\n";
        return true;
    }

private:
    std::unordered_map<uint32_t, NodeMetrics> nodes_;
    std::unordered_map<uint32_t, Ptr<Node>> nodePtrs_;
    Time first_send_time_ = Seconds(0);
    Time last_activity_time_ = Seconds(0);
    std::mutex mu_;
    std::unordered_map<uint32_t, std::map<std::string, CryptoOpStats>> crypto_ops_;

    // helper to get BasicEnergySource (returns nullptr if none)
    Ptr<ns3::energy::BasicEnergySource> GetBasicEnergySource(Ptr<Node> node) {
        if (!node) return nullptr;
        return node->GetObject<ns3::energy::BasicEnergySource>();
    }

    // NON-locking function: capture final energy; caller must hold mu_
    void CaptureFinalEnergyStatesUnlocked() {
        for (auto &p : nodePtrs_) {
            uint32_t idx = p.first;
            Ptr<Node> node = p.second;
            Ptr<ns3::energy::BasicEnergySource> bes = GetBasicEnergySource(node);
            nodes_[idx].final_energy_j = (bes ? bes->GetRemainingEnergy() : 0.0);
        }
    }

    // CSV escape (for inner content only; caller wraps in quotes)
    static std::string EscapeCsv(const std::string &s) {
        std::string out;
        out.reserve(s.size() + 4);
        for (char c : s) {
            if (c == '"') out += "\"\"";
            else out += c;
        }
        return out;
    }
};

} // namespace metrics
