// simulations/auth_scenario.cc
//
// Simple ns-3 scenario demonstrating:
//  - a foreign UAV (node 0) authenticating to a Base Station (node N-1)
//    through intermediate relay UAVs using AODV routing.
//  - uses AuthManager + SodiumCrypto backend for auth messages
//  - collects basic metrics via MetricsCollector
//
// Build: make sure your CMake links against ns-3 and your project library.
// Run: Simulator::Run() will execute and at the end metrics will be printed.
//
// Notes:
//  - This file assumes the helper modules exist:
//      aodv_bridge::Ns3Helper (ns3_helpers.cpp)
//      uavauth::AuthManager (auth_manager.cpp)
//      uavcrypto::CreateCryptoBackend() (sodium_crypto.cpp)
//      metrics::MetricsCollector (metrics_collector.cpp)
//  - Ports: BS listens on RX_PORT (9000) for auth requests; UAV listens on RESPONSE_PORT (9001).

#include <ns3/core-module.h>
#include <ns3/network-module.h>
#include <ns3/internet-module.h>

#include <iostream>
#include <memory>
#include <chrono>

#include "aodv_bridge/ns3_helpers.cpp"         // assuming single-file layout; or include header if available
#include "auth/auth_manager.cpp"               // same assumption: direct compile unit inclusion ok
#include "crypto/sodium_crypto.cpp"            // to get CreateCryptoBackend()
#include "metrics/metrics_collector.cpp"       // metrics

// If you compiled modules separately, include their headers instead and link with the library.

using namespace ns3;
using namespace std::chrono;
using namespace ns3bridge;
using namespace uavauth;
using namespace uavcrypto;
using namespace metrics;

static const uint16_t RX_PORT = 9000;
static const uint16_t RESPONSE_PORT = 9001;

int main(int argc, char **argv) {
    CommandLine cmd;
    uint32_t nodeCount = 5; // default: {0:foreign UAV, 1..3 relays, 4:BS}
    double simDuration = 10.0; // seconds
    cmd.AddValue("nodes", "Number of nodes (min 3)", nodeCount);
    cmd.AddValue("time", "Simulation time (s)", simDuration);
    cmd.Parse(argc, argv);

    if (nodeCount < 3) nodeCount = 3;

    // Create helpers
    Ns3Helper helper;
    helper.BuildWifiNodes(nodeCount);
    helper.InstallAodvRouting();
    helper.AssignIpv4Addresses("10.1.1.0", "255.255.255.0");

    // Indices
    uint32_t foreignIdx = 0;
    uint32_t bsIdx = nodeCount - 1;

    Ipv4Address foreignIp = helper.GetNodeIpv4(foreignIdx);
    Ipv4Address bsIp = helper.GetNodeIpv4(bsIdx);

    std::cout << "Foreign UAV IP: " << foreignIp << "\n";
    std::cout << "BS IP: " << bsIp << "\n";

    // Create crypto backends and auth managers for UAV and BS
    auto crypto_uav = CreateCryptoBackend();
    auto crypto_bs = CreateCryptoBackend();

    auto auth_uav = CreateAuthManager(std::move(crypto_uav));
    auto auth_bs  = CreateAuthManager(std::move(crypto_bs));

    // Metrics collector
    auto collector = std::make_shared<MetricsCollector>();
    for (uint32_t i = 0; i < nodeCount; ++i) {
        collector->RegisterNode(i, helper.GetNode(i));
    }

    // Pre-generate BS Ed25519 keypair (so BS has stable identity)
    // We'll use the crypto backend inside auth_bs to get a keypair by calling GenerateEd25519Keypair via a temporary ICrypto.
    // But auth_manager does not expose direct keypair generation function; for simplicity, instantiate another backend to generate keys.
    auto tempCrypto = CreateCryptoBackend();
    auto bs_keys = tempCrypto->GenerateEd25519Keypair();
    if (!bs_keys.ok) {
        std::cerr << "BS key generation failed: " << bs_keys.err << "\n";
        return 1;
    }
    // split sk||pk (libsodium returns 64||32)
    std::vector<uint8_t> bs_sk(bs_keys.data.begin(), bs_keys.data.begin() + 64);
    std::vector<uint8_t> bs_pk(bs_keys.data.begin() + 64, bs_keys.data.end());

    // UAV generates its AuthRequest at scheduled time and sends to BS
    Simulator::Schedule(Seconds(1.0), [&]() {
        // Measure crypto time for keygen+sign
        auto t0 = high_resolution_clock::now();
        AuthRequest req = auth_uav->GenerateAuthRequest();
        auto t1 = high_resolution_clock::now();
        auto dur = duration_cast<microseconds>(t1 - t0).count();
        collector->AddCryptoTimeUs(foreignIdx, static_cast<uint64_t>(dur));

        // Serialize and send to BS
        auto wire = req.serialize();
        collector->OnPacketSent(foreignIdx, wire.size());
        bool ok = helper.SendUdpBytes(foreignIdx, bsIp, RX_PORT, wire);
        if (!ok) {
            std::cerr << "Failed to send AuthRequest\n";
        } else {
            std::cout << "AuthRequest sent from node " << foreignIdx << " to BS\n";
        }
    });

    // BS receiver: on receiving AuthRequest, verify and send AuthAck back to sender
    helper.RegisterUdpReceiver(bsIdx, RX_PORT, [&](Ipv4Address from, std::vector<uint8_t> payload) {
        // Parse request
        auto maybe = uavauth::AuthRequest::deserialize(payload);
        if (!maybe) {
            std::cerr << "BS: failed to parse AuthRequest\n";
            return;
        }
        AuthRequest req = *maybe;

        // Record packet reception; convert timestamp (we used ms) to seconds
        double sendTimeSec = static_cast<double>(req.timestamp) / 1000.0;
        collector->OnPacketReceived(bsIdx, payload.size(), sendTimeSec);

        // Verify & respond (measure crypto time)
        auto t0 = high_resolution_clock::now();
        AuthAck ack = auth_bs->VerifyAndRespondAuthRequest(req, bs_sk, bs_pk);
        auto t1 = high_resolution_clock::now();
        auto dur = duration_cast<microseconds>(t1 - t0).count();
        collector->AddCryptoTimeUs(bsIdx, static_cast<uint64_t>(dur));

        // Serialize and send ack back to 'from' address (origin IP)
        auto wire = ack.serialize();
        collector->OnPacketSent(bsIdx, wire.size());

        // send to the original sender IP on RESPONSE_PORT
        helper.SendUdpBytes(bsIdx, from, RESPONSE_PORT, wire);
        std::cout << "BS: AuthAck sent to " << from << "\n";
    });

    // UAV receiver: listens for AuthAck, verifies and prints result
    helper.RegisterUdpReceiver(foreignIdx, RESPONSE_PORT, [&](Ipv4Address from, std::vector<uint8_t> payload) {
        auto maybe = uavauth::AuthAck::deserialize(payload);
        if (!maybe) {
            std::cerr << "UAV: failed to parse AuthAck\n";
            return;
        }
        AuthAck ack = *maybe;

        // Record reception time (we don't have sendTime here; use current sim time as receiver)
        double sendTimeSec = 0.0; // unknown in this simple flow
        collector->OnPacketReceived(foreignIdx, payload.size(), sendTimeSec);

        // Verify ack and derive session key (measure crypto)
        auto t0 = high_resolution_clock::now();
        bool ok = auth_uav->VerifyAuthAck(ack, bs_pk);
        auto t1 = high_resolution_clock::now();
        auto dur = duration_cast<microseconds>(t1 - t0).count();
        collector->AddCryptoTimeUs(foreignIdx, static_cast<uint64_t>(dur));

        if (ok) {
            std::cout << "UAV: Authenticated with BS successfully. Session key length = "
                      << auth_uav->GetSessionKey().size() << " bytes\n";
        } else {
            std::cout << "UAV: Authentication with BS failed\n";
        }
    });

    // Stop simulation after simDuration seconds
    Simulator::Stop(Seconds(simDuration));
    Simulator::Run();

    // Print metrics
    collector->PrintSummary();
    collector->WriteSummaryCsv("build/metrics_summary.csv");
    collector->WriteNodeDetailsCsv("build/metrics_node_details.csv");

    Simulator::Destroy();
    return 0;
}
