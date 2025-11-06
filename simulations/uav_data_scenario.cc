// simulations/uav_data_scenario.cc
//
// UAV data scenario:
//  - Nodes: 0 = UAV A (sender), 1 = UAV B (receiver), ... , N-1 = BS
//  - Both UAV A and UAV B authenticate to BS (AuthRequest/AuthAck).
//  - BS creates a random group key and sends it encrypted to each UAV using the
//    session key derived during the auth handshake (HKDF -> AEAD key).
//  - UAV A sends multiple encrypted data messages to UAV B using the group key.
//  - MetricsCollector records send/receive counts, delays, crypto CPU times.
//
// This file includes implementation .cpp files for quick testing; in production
// you may want to link object files and include headers instead.

#include <ns3/core-module.h>
#include <ns3/network-module.h>
#include <ns3/internet-module.h>

#include <iostream>
#include <memory>
#include <chrono>
#include <map>
#include <sstream>               // for converting Ipv4Address to string

#include "aodv_bridge/ns3_helpers.cpp"         // Ns3Helper
#include "auth/auth_manager.cpp"               // AuthManager
#include "crypto/sodium_crypto.cpp"            // CreateCryptoBackend()
#include "crypto/hkdf.h"                       // hkdf_sha256
#include "metrics/metrics_collector.cpp"       // MetricsCollector

using namespace ns3;
using namespace std::chrono;
using namespace ns3bridge;
using namespace uavauth;
using namespace uavcrypto;
using namespace metrics;

static const uint16_t AUTH_REQ_PORT = 9000;
static const uint16_t AUTH_ACK_PORT = 9001;
static const uint16_t GROUP_PORT = 9010;
static const uint16_t DATA_PORT = 9020;

int main(int argc, char** argv) {
    CommandLine cmd;
    uint32_t nodeCount = 5; // nodes: 0 (UAV A), 1 (UAV B), 2..N-2 (relays), N-1 (BS)
    double simDuration = 20.0;
    uint32_t dataMessages = 20;
    double dataInterval = 0.2; // seconds between messages
    cmd.AddValue("nodes", "Number of nodes (>=3)", nodeCount);
    cmd.AddValue("time", "Simulation duration (s)", simDuration);
    cmd.AddValue("messages", "Number of data messages to send", dataMessages);
    cmd.AddValue("interval", "Inter-message interval (s)", dataInterval);
    cmd.Parse(argc, argv);

    if (nodeCount < 3) nodeCount = 3;

    // Build network
    Ns3Helper helper;
    helper.BuildWifiNodes(nodeCount);
    helper.InstallAodvRouting();
    helper.AssignIpv4Addresses("10.1.1.0", "255.255.255.0");

    uint32_t uavA_idx = 0;
    uint32_t uavB_idx = 1;
    uint32_t bs_idx = nodeCount - 1;

    Ipv4Address uavA_ip = helper.GetNodeIpv4(uavA_idx);
    Ipv4Address uavB_ip = helper.GetNodeIpv4(uavB_idx);
    Ipv4Address bs_ip   = helper.GetNodeIpv4(bs_idx);

    std::cout << "UAV A IP: " << uavA_ip << ", UAV B IP: " << uavB_ip << ", BS IP: " << bs_ip << "\n";

    // Metrics
    auto collector = std::make_shared<MetricsCollector>();
    for (uint32_t i = 0; i < nodeCount; ++i) {
        collector->RegisterNode(i, helper.GetNode(i));
    }

    // Create crypto backends & auth managers
    auto crypto_uavA = CreateCryptoBackend();
    auto crypto_uavB = CreateCryptoBackend();
    auto crypto_bs   = CreateCryptoBackend();

    auto auth_uavA = CreateAuthManager(std::move(crypto_uavA));
    auto auth_uavB = CreateAuthManager(std::move(crypto_uavB));
    auto auth_bs   = CreateAuthManager(std::move(crypto_bs));

    // Pre-generate BS Ed25519 keypair
    auto tempCrypto = CreateCryptoBackend();
    auto bs_keys = tempCrypto->GenerateEd25519Keypair();
    if (!bs_keys.ok) {
        std::cerr << "BS keygen failed: " << bs_keys.err << "\n";
        return 1;
    }
    std::vector<uint8_t> bs_sk(bs_keys.data.begin(), bs_keys.data.begin() + 64);
    std::vector<uint8_t> bs_pk(bs_keys.data.begin() + 64, bs_keys.data.end());

    // State trackers
    bool uavA_authed = false;
    bool uavB_authed = false;
    std::map<std::string, std::vector<uint8_t>> bs_session_map; // ip->session_key (as bytes)
    std::vector<uint8_t> uavA_session_key, uavB_session_key;
    std::vector<uint8_t> group_key; // 32 bytes

    // Helper: convert Ipv4Address to key string via stream operator
    auto ipKey = [](const Ipv4Address& ip) {
        std::ostringstream oss;
        oss << ip;
        return oss.str();
    };

    // --- BS receiver: handle AuthRequest from UAVs, verify and respond ---
    helper.RegisterUdpReceiver(bs_idx, AUTH_REQ_PORT, [&](Ipv4Address from, std::vector<uint8_t> payload) {
        auto maybe = uavauth::AuthRequest::deserialize(payload);
        if (!maybe) {
            std::cerr << "BS: failed to parse AuthRequest\n";
            return;
        }
        AuthRequest req = *maybe;

        // record reception (use req.timestamp which is ms since epoch)
        double sendTime = static_cast<double>(req.timestamp) / 1000.0;
        collector->OnPacketReceived(bs_idx, payload.size(), sendTime);

        // Verify and respond. Measure crypto time
        auto t0 = high_resolution_clock::now();
        AuthAck ack = auth_bs->VerifyAndRespondAuthRequest(req, bs_sk, bs_pk);
        auto t1 = high_resolution_clock::now();
        auto dur = duration_cast<microseconds>(t1 - t0).count();
        collector->AddCryptoTimeUs(bs_idx, static_cast<uint64_t>(dur));

        // DEBUG: print ack status/message and derived session key info
        std::cout << "BS: VerifyAndRespondAuthRequest -> status=" << ack.status
                  << " msg=\"" << ack.msg << "\"" << std::endl;

        // After verification succeeded, auth_bs may have internal session material.
        // Capture that session key for this UAV under its IP string so BS can later encrypt group key.
        if (ack.status == 0) {
            std::vector<uint8_t> sess = auth_bs->GetSessionKey();
            std::cout << "BS: derived session key len=" << sess.size() << " bytes\n";
            if (!sess.empty()) {
                std::cout << "BS: session key prefix (hex): ";
                for (size_t i = 0; i < std::min<size_t>(sess.size(), 16); ++i) printf("%02x", sess[i]);
                std::cout << std::endl;
                bs_session_map[ipKey(from)] = sess;
                std::cout << "BS: stored session key for " << from << " (len=" << sess.size() << ")\n";
            } else {
                std::cerr << "BS: WARNING - session key empty after successful ack\n";
            }
        } else {
            std::cerr << "BS: auth failed for " << from << " (" << ack.msg << ")\n";
        }

        // send ack back to sender
        auto wire = ack.serialize();
        collector->OnPacketSent(bs_idx, wire.size());
        helper.SendUdpBytes(bs_idx, from, AUTH_ACK_PORT, wire);
        std::cout << "BS: AuthAck sent to " << from << "\n";
    });

    // --- UAV A receiver: listens for AuthAck and GroupKey and Data ---
    helper.RegisterUdpReceiver(uavA_idx, AUTH_ACK_PORT, [&](Ipv4Address from, std::vector<uint8_t> payload) {
        auto maybe = uavauth::AuthAck::deserialize(payload);
        if (!maybe) {
            std::cerr << "UAV A: failed to parse AuthAck\n";
            return;
        }
        AuthAck ack = *maybe;

        // record reception; no sendTime available for ack (use current sim time)
        collector->OnPacketReceived(uavA_idx, payload.size(), 0.0);

        // Verify and derive session key
        auto t0 = high_resolution_clock::now();
        bool ok = auth_uavA->VerifyAuthAck(ack, bs_pk);
        auto t1 = high_resolution_clock::now();
        collector->AddCryptoTimeUs(uavA_idx, static_cast<uint64_t>(duration_cast<microseconds>(t1 - t0).count()));

        if (ok) {
            uavA_authed = true;
            uavA_session_key = auth_uavA->GetSessionKey();
            std::cout << "UAV A: Authenticated to BS, session key len=" << uavA_session_key.size() << "\n";
        } else {
            std::cerr << "UAV A: AuthAck verification failed\n";
        }
    });

    helper.RegisterUdpReceiver(uavB_idx, AUTH_ACK_PORT, [&](Ipv4Address from, std::vector<uint8_t> payload) {
        auto maybe = uavauth::AuthAck::deserialize(payload);
        if (!maybe) {
            std::cerr << "UAV B: failed to parse AuthAck\n";
            return;
        }
        AuthAck ack = *maybe;
        collector->OnPacketReceived(uavB_idx, payload.size(), 0.0);

        auto t0 = high_resolution_clock::now();
        bool ok = auth_uavB->VerifyAuthAck(ack, bs_pk);
        auto t1 = high_resolution_clock::now();
        collector->AddCryptoTimeUs(uavB_idx, static_cast<uint64_t>(duration_cast<microseconds>(t1 - t0).count()));

        if (ok) {
            uavB_authed = true;
            uavB_session_key = auth_uavB->GetSessionKey();
            std::cout << "UAV B: Authenticated to BS, session key len=" << uavB_session_key.size() << "\n";
        } else {
            std::cerr << "UAV B: AuthAck verification failed\n";
        }
    });

    // Group key receiver: BS will send an AEAD-encrypted group key to each UAV on GROUP_PORT.
    // UAV A: derive AEAD key via HKDF from session material, then decrypt.
    helper.RegisterUdpReceiver(uavA_idx, GROUP_PORT, [&](Ipv4Address from, std::vector<uint8_t> payload) {
        if (uavA_session_key.empty()) {
            std::cerr << "UAV A: no session key available to decrypt group key\n";
            return;
        }
        // derive AEAD key (32 bytes) using HKDF-SHA256 with an info label
        std::vector<uint8_t> aeadKeyA = uavcrypto::hkdf_sha256(std::vector<uint8_t>{}, uavA_session_key, std::vector<uint8_t>{'g','r','o','u','p','A'}, 32);
        if (aeadKeyA.size() != 32) {
            std::cerr << "UAV A: hkdf failed to produce 32-byte key\n";
            return;
        }

        auto crypto = CreateCryptoBackend();
        auto dec = crypto->AeadDecrypt(aeadKeyA, {}, payload);
        if (!dec.ok) {
            std::cerr << "UAV A: failed to decrypt group key: " << dec.err << "\n";
            return;
        }
        group_key = dec.data;
        std::cout << "UAV A: received group key (len=" << group_key.size() << ")\n";
        collector->OnPacketReceived(uavA_idx, payload.size(), 0.0);
    });

    // UAV B group key receiver (derives its own AEAD key)
    helper.RegisterUdpReceiver(uavB_idx, GROUP_PORT, [&](Ipv4Address from, std::vector<uint8_t> payload) {
        if (uavB_session_key.empty()) {
            std::cerr << "UAV B: no session key available to decrypt group key\n";
            return;
        }
        std::vector<uint8_t> aeadKeyB = uavcrypto::hkdf_sha256(std::vector<uint8_t>{}, uavB_session_key, std::vector<uint8_t>{'g','r','o','u','p','B'}, 32);
        if (aeadKeyB.size() != 32) {
            std::cerr << "UAV B: hkdf failed to produce 32-byte key\n";
            return;
        }
        auto crypto = CreateCryptoBackend();
        auto dec = crypto->AeadDecrypt(aeadKeyB, {}, payload);
        if (!dec.ok) {
            std::cerr << "UAV B: failed to decrypt group key: " << dec.err << "\n";
            return;
        }
        group_key = dec.data;
        std::cout << "UAV B: received group key (len=" << group_key.size() << ")\n";
        collector->OnPacketReceived(uavB_idx, payload.size(), 0.0);
    });

    // Data receiver on UAV B: decrypts messages using group_key and records metrics
    helper.RegisterUdpReceiver(uavB_idx, DATA_PORT, [&](Ipv4Address from, std::vector<uint8_t> payload) {
        if (group_key.empty()) {
            std::cerr << "UAV B: no group key yet for decrypting data\n";
            return;
        }
        auto crypto = CreateCryptoBackend();

        auto dec = crypto->AeadDecrypt(group_key, {}, payload);
        if (!dec.ok) {
            std::cerr << "UAV B: data decrypt failed: " << dec.err << "\n";
            return;
        }
        if (dec.data.size() < sizeof(double)) {
            std::cerr << "UAV B: decrypted data too small\n";
            return;
        }
        double send_time_s = 0.0;
        std::memcpy(&send_time_s, dec.data.data(), sizeof(double));
        size_t app_size = dec.data.size() - sizeof(double);

        collector->OnPacketReceived(uavB_idx, payload.size(), send_time_s);

        static uint32_t recv_count = 0;
        recv_count++;
        if ((recv_count % 5) == 0) {
            std::cout << "UAV B: received message #" << recv_count << " (app bytes=" << app_size << ")\n";
        }
    });

    // Schedule: at t=1s both UAVs send AuthRequest to BS
    Simulator::Schedule(Seconds(2.0), [&]() {
        auto t0 = high_resolution_clock::now();
        AuthRequest reqA = auth_uavA->GenerateAuthRequest();
        auto t1 = high_resolution_clock::now();
        collector->AddCryptoTimeUs(uavA_idx, static_cast<uint64_t>(duration_cast<microseconds>(t1 - t0).count()));

        auto wireA = reqA.serialize();
        collector->OnPacketSent(uavA_idx, wireA.size());
        helper.SendUdpBytes(uavA_idx, bs_ip, AUTH_REQ_PORT, wireA);
        std::cout << "UAV A: sent AuthRequest to BS\n";

        auto t2 = high_resolution_clock::now();
        AuthRequest reqB = auth_uavB->GenerateAuthRequest();
        auto t3 = high_resolution_clock::now();
        collector->AddCryptoTimeUs(uavB_idx, static_cast<uint64_t>(duration_cast<microseconds>(t3 - t2).count()));

        auto wireB = reqB.serialize();
        collector->OnPacketSent(uavB_idx, wireB.size());
        helper.SendUdpBytes(uavB_idx, bs_ip, AUTH_REQ_PORT, wireB);
        std::cout << "UAV B: sent AuthRequest to BS\n";
    });

    // After a short delay (allow BS to process both auths), BS generates group key and distributes.
    Simulator::Schedule(Seconds(6.0), [&]() {
        std::string keyA = ipKey(uavA_ip);
        std::string keyB = ipKey(uavB_ip);
        if (bs_session_map.find(keyA) == bs_session_map.end() ||
            bs_session_map.find(keyB) == bs_session_map.end()) {
            std::cerr << "BS: session keys missing for one or both UAVs; skipping group distribution\n";
            return;
        }

        std::vector<uint8_t> gk(32);
        randombytes_buf(gk.data(), gk.size());
        std::cout << "BS: generated group key (len=" << gk.size() << ")\n";

        // Encrypt group key for UAV A using HKDF-derived AEAD key
        {
            auto crypto_local = CreateCryptoBackend();
            auto sessA = bs_session_map[keyA];
            std::vector<uint8_t> aeadKeyA = uavcrypto::hkdf_sha256(std::vector<uint8_t>{}, sessA, std::vector<uint8_t>{'g','r','o','u','p','A'}, 32);
            if (aeadKeyA.size() != 32) {
                std::cerr << "BS: hkdf failed to produce 32-byte key for UAV A\n";
            } else {
                auto ctA = crypto_local->AeadEncrypt(aeadKeyA, {}, gk);
                if (!ctA.ok) {
                    std::cerr << "BS: failed to encrypt group key for UAV A: " << ctA.err << "\n";
                } else {
                    collector->OnPacketSent(bs_idx, ctA.data.size());
                    helper.SendUdpBytes(bs_idx, uavA_ip, GROUP_PORT, ctA.data);
                    std::cout << "BS: sent encrypted group key to UAV A\n";
                }
            }
        }

        // Encrypt group key for UAV B using HKDF-derived AEAD key
        {
            auto crypto_local = CreateCryptoBackend();
            auto sessB = bs_session_map[keyB];
            std::vector<uint8_t> aeadKeyB = uavcrypto::hkdf_sha256(std::vector<uint8_t>{}, sessB, std::vector<uint8_t>{'g','r','o','u','p','B'}, 32);
            if (aeadKeyB.size() != 32) {
                std::cerr << "BS: hkdf failed to produce 32-byte key for UAV B\n";
            } else {
                auto ctB = crypto_local->AeadEncrypt(aeadKeyB, {}, gk);
                if (!ctB.ok) {
                    std::cerr << "BS: failed to encrypt group key for UAV B: " << ctB.err << "\n";
                } else {
                    collector->OnPacketSent(bs_idx, ctB.data.size());
                    helper.SendUdpBytes(bs_idx, uavB_ip, GROUP_PORT, ctB.data);
                    std::cout << "BS: sent encrypted group key to UAV B\n";
                }
            }
        }
    });

    // After another short delay to allow group key reception, schedule data messages from UAV A to UAV B using group_key.
    Simulator::Schedule(Seconds(8.0), [&]() {
        if (group_key.empty()) {
            std::cerr << "UAV A: no group key locally yet; scheduling still proceeds but messages will likely be dropped\n";
        }

        for (uint32_t i = 0; i < dataMessages; ++i) {
            double t = 4.0 + i * dataInterval;
            Simulator::Schedule(Seconds(t), [&, i]() {
                double send_time_s = Simulator::Now().GetSeconds();
                std::string payload_text = "secure message #" + std::to_string(i+1);
                std::vector<uint8_t> plain(sizeof(double) + payload_text.size());
                std::memcpy(plain.data(), &send_time_s, sizeof(double));
                std::memcpy(plain.data() + sizeof(double), payload_text.data(), payload_text.size());

                // If group_key is not present or too small, log and skip to avoid "symmetric key too small"
                if (group_key.size() < 16) {
                    std::cerr << "UAV A: group_key not available or too small; cannot encrypt message\n";
                    return;
                }

                auto crypto_local = CreateCryptoBackend();
                auto ct = crypto_local->AeadEncrypt(group_key, {}, plain);
                if (!ct.ok) {
                    std::cerr << "UAV A: data encrypt failed: " << ct.err << "\n";
                    return;
                }
                collector->OnPacketSent(uavA_idx, ct.data.size());
                helper.SendUdpBytes(uavA_idx, uavB_ip, DATA_PORT, ct.data);
            });
        }
    });

    // Stop simulation
    Simulator::Stop(Seconds(simDuration));
    Simulator::Run();

    // Print metrics
    collector->PrintSummary();
    collector->WriteSummaryCsv("build/metrics_summary.csv");
    collector->WriteNodeDetailsCsv("build/metrics_node_details.csv");

    // Optionally write CSV (uncomment if WriteCsv exists)
    // std::ostringstream oss;
    // auto tnow = std::time(nullptr);
    // oss << "logs/metrics-" << std::put_time(std::localtime(&tnow), "%Y%m%d-%H%M%S") << ".csv";
    // collector->WriteCsv(oss.str());

    Simulator::Destroy();
    return 0;
}
