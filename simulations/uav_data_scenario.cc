// simulations/uav_data_scenario.cc
//
// Simplified UAV data scenario with a small watchdog to avoid permanent hang
// after Simulator::Run(). Writes CSV summary + text summary into a timestamped
// results directory.
//
// This file purposely includes implementation units for quick testing (same
// as your previous layout). In production prefer headers + linking.

#include <ns3/core-module.h>
#include <ns3/network-module.h>
#include <ns3/internet-module.h>
#include <ns3/energy-module.h>

#include <iostream>
#include <memory>
#include <chrono>
#include <map>
#include <sstream>
#include <filesystem>
#include <ctime>
#include <iomanip>
#include <fstream>
#include <cstring>
#include <thread>
#include <atomic>
#include <unistd.h> // getcwd

// local components (as in your tree)
#include "aodv_bridge/ns3_helpers.cpp"
#include "auth/auth_manager.cpp"
#include "auth/auth_messages.h"   // <-- new header with timestamped messages
#include "crypto/sodium_crypto.cpp"
#include "crypto/hkdf.h"
#include "metrics/metrics_collector.cpp"

using namespace ns3;
using namespace ns3bridge;
using namespace uavauth;
using namespace uavcrypto;
using namespace metrics;

static const uint16_t AUTH_REQ_PORT = 9000;
static const uint16_t AUTH_ACK_PORT = 9001;
static const uint16_t GROUP_PORT    = 9010;
static const uint16_t DATA_PORT     = 9020;

int main(int argc, char** argv) {
    CommandLine cmd;
    uint32_t nodeCount = 5;
    double simDuration = 20.0;
    uint32_t dataMessages = 20;
    double dataInterval = 0.2;
    std::string outBase = "results";
    double grace = 5.0; // watchdog grace (seconds) beyond simDuration

    cmd.AddValue("nodes",    "Number of nodes (>=3)", nodeCount);
    cmd.AddValue("time",     "Simulation duration (s)", simDuration);
    cmd.AddValue("messages", "Number of data messages to send", dataMessages);
    cmd.AddValue("interval", "Inter-message interval (s)", dataInterval);
    cmd.AddValue("outdir",   "Base output directory (default: results)", outBase);
    cmd.AddValue("grace",    "Watchdog grace period (s) added to simDuration before forced shutdown", grace);
    cmd.Parse(argc, argv);

    if (nodeCount < 3) nodeCount = 3;

    // prepare timestamped output directory
    std::filesystem::path basePath(outBase);
    std::time_t tnow = std::time(nullptr);
    std::tm tmnow;
#if defined(_WIN32)
    gmtime_s(&tmnow, &tnow);
#else
    gmtime_r(&tnow, &tmnow);
#endif
    std::ostringstream ts;
    ts << std::put_time(&tmnow, "%Y%m%d-%H%M%S");
    std::filesystem::path outDir = basePath / ts.str();

    try {
        std::filesystem::create_directories(outDir);
    } catch (const std::exception &e) {
        std::cerr << "[ERR] Failed to create output directory '" << outDir.string() << "': " << e.what() << "\n";
        return 1;
    }

    std::cerr << "[INFO] Outputs will be written to: " << outDir << "\n";

    // print working dir to help debugging
    {
        char *cwd = getcwd(nullptr, 0);
        if (cwd) {
            std::cerr << "[DEBUG] cwd = " << cwd << "\n";
            free(cwd);
        }
    }

    // Build simple network + routing
    Ns3Helper helper;
    helper.BuildWifiNodes(nodeCount);
    helper.InstallAodvRouting();
    helper.AssignIpv4Addresses("10.1.1.0", "255.255.255.0");

    uint32_t uavA_idx = 0;
    uint32_t uavB_idx = 1;
    uint32_t bs_idx   = nodeCount - 1;

    Ipv4Address uavA_ip = helper.GetNodeIpv4(uavA_idx);
    Ipv4Address uavB_ip = helper.GetNodeIpv4(uavB_idx);
    Ipv4Address bs_ip   = helper.GetNodeIpv4(bs_idx);

    std::cerr << "[INFO] UAV A IP: " << uavA_ip << "  UAV B IP: " << uavB_ip << "  BS IP: " << bs_ip << "\n";

    // --- Install energy sources before registering nodes so initial energy is captured
    ns3::BasicEnergySourceHelper esHelper;
    // set a sensible default initial energy (J). Adjust as you like.
    esHelper.Set("BasicEnergySourceInitialEnergyJ", DoubleValue(500.0));

    ns3::NodeContainer nodes;
    for (uint32_t i = 0; i < nodeCount; ++i) {
        nodes.Add(helper.GetNode(i));
    }
    // capture the returned container so we can query energy sources reliably
    ns3::energy::EnergySourceContainer esc = esHelper.Install(nodes);
    std::cerr << "[INFO] Installed BasicEnergySource on " << nodeCount << " nodes\n";

    // Install per-device radio energy model (attach to energy sources)
    ns3::WifiRadioEnergyModelHelper radioHelper;
    radioHelper.Set("TxCurrentA", DoubleValue(0.038));
    radioHelper.Set("RxCurrentA", DoubleValue(0.021));
    radioHelper.Set("IdleCurrentA", DoubleValue(0.005));
    radioHelper.Set("SleepCurrentA", DoubleValue(0.001));
    NetDeviceContainer devs = helper.GetDeviceContainer();
    ns3::energy::DeviceEnergyModelContainer demc = radioHelper.Install(devs, esc);
    std::cerr << "[INFO] Installed WifiRadioEnergyModel models=" << demc.GetN() << "\n";

    // Metrics collector (register nodes AFTER energy sources were installed)
    auto collector = std::make_shared<MetricsCollector>();
    for (uint32_t i = 0; i < nodeCount; ++i) {
        collector->RegisterNode(i, helper.GetNode(i));
    }

    // Register explicit energy sources from esc into collector so we can reliably read them later
    for (uint32_t i = 0; i < esc.GetN() && i < nodeCount; ++i) {
        Ptr<ns3::energy::EnergySource> es = esc.Get(i); // base class pointer in ns3::energy
        if (!es) {
            std::cerr << "[WARN] esc.Get(" << i << ") returned nullptr\n";
            continue;
        }
        Ptr<ns3::energy::BasicEnergySource> src = DynamicCast<ns3::energy::BasicEnergySource>(es);
        if (!src) {
            std::cerr << "[WARN] esc.Get(" << i << ") is not a BasicEnergySource (type may differ)\n";
            continue;
        }
        collector->RegisterEnergySource(i, src);
        std::cerr << "[INFO] Registered energy source for node " << i << " initialE=" << src->GetRemainingEnergy() << " J\n";
    }

    // Debug: print initial energy values for verification (use esc instead of node->GetObject)
    for (uint32_t i = 0; i < esc.GetN() && i < nodeCount; ++i) {
        Ptr<ns3::energy::EnergySource> es = esc.Get(i);
        if (!es) {
            std::cerr << "[DEBUG] node " << i << " has NO EnergySource\n";
            continue;
        }
        Ptr<ns3::energy::BasicEnergySource> bes = DynamicCast<ns3::energy::BasicEnergySource>(es);
        if (bes) {
            std::cerr << "[DEBUG] node " << i << " initial energy = " << bes->GetRemainingEnergy() << " J\n";
        } else {
            std::cerr << "[DEBUG] node " << i << " energy source is not BasicEnergySource\n";
        }
    }

    // crypto / auth managers
    auto crypto_uavA = CreateCryptoBackend();
    auto crypto_uavB = CreateCryptoBackend();
    auto crypto_bs   = CreateCryptoBackend();

    auto auth_uavA = CreateAuthManager(std::move(crypto_uavA));
    auto auth_uavB = CreateAuthManager(std::move(crypto_uavB));
    auto auth_bs   = CreateAuthManager(std::move(crypto_bs));

    // BS keypair
    auto tempCrypto = CreateCryptoBackend();
    auto bs_keys = tempCrypto->GenerateEd25519Keypair();
    if (!bs_keys.ok) {
        std::cerr << "[ERR] BS key generation failed: " << bs_keys.err << "\n";
        return 1;
    }
    std::vector<uint8_t> bs_sk(bs_keys.data.begin(), bs_keys.data.begin() + 64);
    std::vector<uint8_t> bs_pk(bs_keys.data.begin() + 64, bs_keys.data.end());

    // state
    std::map<std::string, std::vector<uint8_t>> bs_sessions;
    std::vector<uint8_t> uavA_session, uavB_session, group_key;

    auto ipKey = [](const Ipv4Address& ip) {
        std::ostringstream o; o << ip; return o.str();
    };

    // ---- BS receiver: handle AuthRequest
    helper.RegisterUdpReceiver(bs_idx, AUTH_REQ_PORT, [&](Ipv4Address from, std::vector<uint8_t> payload) {
        auto maybe = uavauth::AuthRequest::deserialize(payload);
        if (!maybe) {
            std::cerr << "[BS] failed to parse AuthRequest\n";
            return;
        }
        AuthRequest req = *maybe;

        // Use the sender's embedded timestamp for delay measurement (accurate)
        collector->OnPacketReceived(bs_idx, payload.size(), req.send_time_s);

        auto t0 = std::chrono::high_resolution_clock::now();
        AuthAck ack = auth_bs->VerifyAndRespondAuthRequest(req, bs_sk, bs_pk);
        auto t1 = std::chrono::high_resolution_clock::now();
        uint64_t dur = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
        collector->AddCryptoTimeUs(bs_idx, dur);
        collector->AddCryptoOp(bs_idx, "AUTH_VERIFY", dur);

        std::cerr << "[BS] VerifyAndRespondAuthRequest -> status=" << ack.status << " msg=\"" << ack.msg << "\"\n";

        if (ack.status == 0) {
            std::vector<uint8_t> sess = auth_bs->GetSessionKey();
            if (!sess.empty()) {
                bs_sessions[ipKey(from)] = sess;
                std::cerr << "[BS] stored session for " << from << " (len=" << sess.size() << ")\n";
            }
        }

        // stamp ack with BS send time and serialize
        ack.send_time_s = Simulator::Now().GetSeconds();
        auto wire = ack.serialize();
        collector->OnPacketSent(bs_idx, wire.size());
        helper.SendUdpBytes(bs_idx, from, AUTH_ACK_PORT, wire);
    });

    // ---- UAV A/B receivers for AuthAck
    helper.RegisterUdpReceiver(uavA_idx, AUTH_ACK_PORT, [&](Ipv4Address, std::vector<uint8_t> payload) {
        auto maybe = uavauth::AuthAck::deserialize(payload);
        if (!maybe) { std::cerr << "[UAV A] failed to parse AuthAck\n"; return; }
        AuthAck ack = *maybe;
        // record receive using sender's embedded send_time (accurate)
        collector->OnPacketReceived(uavA_idx, payload.size(), ack.send_time_s);
        auto t0 = std::chrono::high_resolution_clock::now();
        bool ok = auth_uavA->VerifyAuthAck(ack, bs_pk);
        auto t1 = std::chrono::high_resolution_clock::now();
        uint64_t dur = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
        collector->AddCryptoTimeUs(uavA_idx, dur);
        collector->AddCryptoOp(uavA_idx, "AUTH_ACK_VERIFY", dur);
        if (ok) { uavA_session = auth_uavA->GetSessionKey(); std::cerr << "[UAV A] authenticated (sess len=" << uavA_session.size() << ")\n"; }
    });

    helper.RegisterUdpReceiver(uavB_idx, AUTH_ACK_PORT, [&](Ipv4Address, std::vector<uint8_t> payload) {
        auto maybe = uavauth::AuthAck::deserialize(payload);
        if (!maybe) { std::cerr << "[UAV B] failed to parse AuthAck\n"; return; }
        AuthAck ack = *maybe;
        // record receive using sender's embedded send_time (accurate)
        collector->OnPacketReceived(uavB_idx, payload.size(), ack.send_time_s);
        auto t0 = std::chrono::high_resolution_clock::now();
        bool ok = auth_uavB->VerifyAuthAck(ack, bs_pk);
        auto t1 = std::chrono::high_resolution_clock::now();
        uint64_t dur = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
        collector->AddCryptoTimeUs(uavB_idx, dur);
        collector->AddCryptoOp(uavB_idx, "AUTH_ACK_VERIFY", dur);
        if (ok) { uavB_session = auth_uavB->GetSessionKey(); std::cerr << "[UAV B] authenticated (sess len=" << uavB_session.size() << ")\n"; }
    });

    // ---- Group key receivers
    helper.RegisterUdpReceiver(uavA_idx, GROUP_PORT, [&](Ipv4Address, std::vector<uint8_t> payload) {
        if (uavA_session.empty()) { std::cerr << "[UAV A] no session to decrypt group\n"; return; }
        std::vector<uint8_t> aead = uavcrypto::hkdf_sha256({}, uavA_session, std::vector<uint8_t>{'g','r','o','u','p','A'}, 32);
        auto crypto = CreateCryptoBackend();
        auto t0 = std::chrono::high_resolution_clock::now();
        auto dec = crypto->AeadDecrypt(aead, {}, payload);
        auto t1 = std::chrono::high_resolution_clock::now();
        uint64_t dur = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
        collector->AddCryptoTimeUs(uavA_idx, dur);
        collector->AddCryptoOp(uavA_idx, "AEAD_DECRYPT_GROUP", dur);
        if (!dec.ok) { std::cerr << "[UAV A] group decrypt failed: " << dec.err << "\n"; return; }
        // decrypted plaintext layout: [8-byte double send_time] [group_key (32 bytes)]
        if (dec.data.size() < sizeof(double) + 16) {
            std::cerr << "[UAV A] group plaintext too small\n"; return;
        }
        double send_time_s = 0.0;
        std::memcpy(&send_time_s, dec.data.data(), sizeof(double));
        group_key.assign(dec.data.begin() + sizeof(double), dec.data.end());
        collector->OnPacketReceived(uavA_idx, payload.size(), send_time_s);
        std::cerr << "[UAV A] got group key (len=" << group_key.size() << ", send_time=" << send_time_s << ")\n";
    });

    helper.RegisterUdpReceiver(uavB_idx, GROUP_PORT, [&](Ipv4Address, std::vector<uint8_t> payload) {
        if (uavB_session.empty()) { std::cerr << "[UAV B] no session to decrypt group\n"; return; }
        std::vector<uint8_t> aead = uavcrypto::hkdf_sha256({}, uavB_session, std::vector<uint8_t>{'g','r','o','u','p','B'}, 32);
        auto crypto = CreateCryptoBackend();
        auto t0 = std::chrono::high_resolution_clock::now();
        auto dec = crypto->AeadDecrypt(aead, {}, payload);
        auto t1 = std::chrono::high_resolution_clock::now();
        uint64_t dur = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
        collector->AddCryptoTimeUs(uavB_idx, dur);
        collector->AddCryptoOp(uavB_idx, "AEAD_DECRYPT_GROUP", dur);
        if (!dec.ok) { std::cerr << "[UAV B] group decrypt failed: " << dec.err << "\n"; return; }
        if (dec.data.size() < sizeof(double) + 16) {
            std::cerr << "[UAV B] group plaintext too small\n"; return;
        }
        double send_time_s = 0.0;
        std::memcpy(&send_time_s, dec.data.data(), sizeof(double));
        group_key.assign(dec.data.begin() + sizeof(double), dec.data.end());
        collector->OnPacketReceived(uavB_idx, payload.size(), send_time_s);
        std::cerr << "[UAV B] got group key (len=" << group_key.size() << ", send_time=" << send_time_s << ")\n";
    });

    // ---- Data receiver (UAV B)
    helper.RegisterUdpReceiver(uavB_idx, DATA_PORT, [&](Ipv4Address, std::vector<uint8_t> payload) {
        if (group_key.empty()) { std::cerr << "[UAV B] no group key yet\n"; return; }
        auto crypto = CreateCryptoBackend();
        auto t0 = std::chrono::high_resolution_clock::now();
        auto dec = crypto->AeadDecrypt(group_key, {}, payload);
        auto t1 = std::chrono::high_resolution_clock::now();
        uint64_t dur = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
        collector->AddCryptoTimeUs(uavB_idx, dur);
        collector->AddCryptoOp(uavB_idx, "AEAD_DECRYPT_DATA", dur);
        if (!dec.ok) { std::cerr << "[UAV B] data decrypt failed: " << dec.err << "\n"; return; }
        if (dec.data.size() < sizeof(double)) { std::cerr << "[UAV B] decrypted payload too small\n"; return; }
        double send_time_s = 0.0;
        std::memcpy(&send_time_s, dec.data.data(), sizeof(double));
        size_t app_sz = dec.data.size() - sizeof(double);
        collector->OnPacketReceived(uavB_idx, payload.size(), send_time_s);
        static uint32_t recv_count = 0;
        recv_count++;
        if ((recv_count % 5) == 0) std::cerr << "[UAV B] received message #" << recv_count << " (app bytes=" << app_sz << ")\n";
    });

    // ---- Schedule auth requests at t=2.0
    Simulator::Schedule(Seconds(2.0), [&]() {
        // UAV A
        {
            auto t0 = std::chrono::high_resolution_clock::now();
            AuthRequest rA = auth_uavA->GenerateAuthRequest();
            auto t1 = std::chrono::high_resolution_clock::now();
            uint64_t durA = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
            collector->AddCryptoTimeUs(uavA_idx, durA);
            collector->AddCryptoOp(uavA_idx, "AUTH_GEN", durA);

            // stamp sender time (exact simulator time at send)
            rA.send_time_s = Simulator::Now().GetSeconds();
            auto wireA = rA.serialize();
            collector->OnPacketSent(uavA_idx, wireA.size());
            helper.SendUdpBytes(uavA_idx, bs_ip, AUTH_REQ_PORT, wireA);
            std::cerr << "[UAV A] sent AuthRequest (send_time=" << rA.send_time_s << ")\n";
        }

        // UAV B
        {
            auto t2 = std::chrono::high_resolution_clock::now();
            AuthRequest rB = auth_uavB->GenerateAuthRequest();
            auto t3 = std::chrono::high_resolution_clock::now();
            uint64_t durB = std::chrono::duration_cast<std::chrono::microseconds>(t3 - t2).count();
            collector->AddCryptoTimeUs(uavB_idx, durB);
            collector->AddCryptoOp(uavB_idx, "AUTH_GEN", durB);

            rB.send_time_s = Simulator::Now().GetSeconds();
            auto wireB = rB.serialize();
            collector->OnPacketSent(uavB_idx, wireB.size());
            helper.SendUdpBytes(uavB_idx, bs_ip, AUTH_REQ_PORT, wireB);
            std::cerr << "[UAV B] sent AuthRequest (send_time=" << rB.send_time_s << ")\n";
        }
    });

    // ---- BS generate + distribute group key (t=6.0)
    Simulator::Schedule(Seconds(6.0), [&]() {
        auto kA = ipKey(uavA_ip);
        auto kB = ipKey(uavB_ip);
        if (bs_sessions.find(kA) == bs_sessions.end() || bs_sessions.find(kB) == bs_sessions.end()) {
            std::cerr << "[BS] missing session(s) — skipping group distribution\n";
            return;
        }
        std::vector<uint8_t> gk(32);
        randombytes_buf(gk.data(), gk.size());
        std::cerr << "[BS] generated group key\n";

        // stamp timestamp for group distribution (sender time)
        double gsend = Simulator::Now().GetSeconds();

        // encrypt for A (plaintext: [double send_time][group_key])
        {
            std::vector<uint8_t> plain(sizeof(double) + gk.size());
            std::memcpy(plain.data(), &gsend, sizeof(double));
            std::memcpy(plain.data() + sizeof(double), gk.data(), gk.size());

            auto crypto_local = CreateCryptoBackend();
            auto aeadKey = uavcrypto::hkdf_sha256({}, bs_sessions[kA], std::vector<uint8_t>{'g','r','o','u','p','A'}, 32);
            auto t0 = std::chrono::high_resolution_clock::now();
            auto ct = crypto_local->AeadEncrypt(aeadKey, {}, plain);
            auto t1 = std::chrono::high_resolution_clock::now();
            uint64_t dur = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
            collector->AddCryptoTimeUs(bs_idx, dur);
            collector->AddCryptoOp(bs_idx, "AEAD_ENCRYPT_GROUP_A", dur);
            if (!ct.ok) { std::cerr << "[BS] encrypt->A failed: " << ct.err << "\n"; }
            else { collector->OnPacketSent(bs_idx, ct.data.size()); helper.SendUdpBytes(bs_idx, uavA_ip, GROUP_PORT, ct.data); std::cerr << "[BS] sent group->A (send_time=" << gsend << ")\n"; }
        }

        // encrypt for B (same)
        {
            std::vector<uint8_t> plain(sizeof(double) + gk.size());
            std::memcpy(plain.data(), &gsend, sizeof(double));
            std::memcpy(plain.data() + sizeof(double), gk.data(), gk.size());

            auto crypto_local = CreateCryptoBackend();
            auto aeadKey = uavcrypto::hkdf_sha256({}, bs_sessions[kB], std::vector<uint8_t>{'g','r','o','u','p','B'}, 32);
            auto t0 = std::chrono::high_resolution_clock::now();
            auto ct = crypto_local->AeadEncrypt(aeadKey, {}, plain);
            auto t1 = std::chrono::high_resolution_clock::now();
            uint64_t dur = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
            collector->AddCryptoTimeUs(bs_idx, dur);
            collector->AddCryptoOp(bs_idx, "AEAD_ENCRYPT_GROUP_B", dur);
            if (!ct.ok) { std::cerr << "[BS] encrypt->B failed: " << ct.err << "\n"; }
            else { collector->OnPacketSent(bs_idx, ct.data.size()); helper.SendUdpBytes(bs_idx, uavB_ip, GROUP_PORT, ct.data); std::cerr << "[BS] sent group->B (send_time=" << gsend << ")\n"; }
        }

        // store group key locally for BS (if needed)
        group_key = gk;
    });

    // ---- Schedule data sends from A to B (starting t=8.0)
    Simulator::Schedule(Seconds(8.0), [&]() {
        for (uint32_t i = 0; i < dataMessages; ++i) {
            double t = 8.0 + i * dataInterval;
            Simulator::Schedule(Seconds(t), [&, i]() {
                double send_time = Simulator::Now().GetSeconds();
                std::string msg = "secure message #" + std::to_string(i + 1);
                std::vector<uint8_t> plain(sizeof(double) + msg.size());
                std::memcpy(plain.data(), &send_time, sizeof(double));
                std::memcpy(plain.data() + sizeof(double), msg.data(), msg.size());

                if (group_key.size() < 16) { std::cerr << "[UAV A] no group key yet — skipping data encrypt\n"; return; }
                auto crypto_local = CreateCryptoBackend();
                auto t0 = std::chrono::high_resolution_clock::now();
                auto ct = crypto_local->AeadEncrypt(group_key, {}, plain);
                auto t1 = std::chrono::high_resolution_clock::now();
                uint64_t dur = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
                collector->AddCryptoTimeUs(uavA_idx, dur);
                collector->AddCryptoOp(uavA_idx, "AEAD_ENCRYPT_DATA", dur);
                if (!ct.ok) { std::cerr << "[UAV A] data encrypt failed: " << ct.err << "\n"; return; }
                collector->OnPacketSent(uavA_idx, ct.data.size());
                helper.SendUdpBytes(uavA_idx, uavB_ip, DATA_PORT, ct.data);
            });
        }
    });

    // small sim debug prints
    Simulator::Schedule(Seconds(0.5), []() { std::cerr << "[SIMDBG] t=" << Simulator::Now().GetSeconds() << "\n"; });
    Simulator::Schedule(Seconds(simDuration/2.0), []() { std::cerr << "[SIMDBG] half time t=" << Simulator::Now().GetSeconds() << "\n"; });
    Simulator::Schedule(Seconds(simDuration + 0.01), []() { std::cerr << "[SIMDBG] stop deadline t=" << Simulator::Now().GetSeconds() << "\n"; });

    // watchdog: if Simulator::Run() hasn't returned by wall-time (simDuration + grace), force a best-effort write + exit
    std::atomic<bool> run_returned(false);
    std::thread watchdog([&collector, outDir, simDuration, grace, &run_returned]() {
        double wait_seconds = simDuration + grace;
        std::this_thread::sleep_for(std::chrono::duration<double>(wait_seconds));
        if (run_returned.load()) return;
        std::cerr << "[WATCHDOG] timeout (" << wait_seconds << "s) — attempting to write outputs and exit\n";

        try {
            std::filesystem::path csvSummary = outDir / "metrics_summary.csv";
            std::filesystem::path csvDetails = outDir / "metrics_node_details.csv";
            std::filesystem::path txtSummary = outDir / "summary.txt";

            bool ok1 = collector->WriteSummaryCsv(csvSummary.string());
            bool ok2 = collector->WriteNodeDetailsCsv(csvDetails.string());
            std::cerr << "[WATCHDOG] WriteSummaryCsv -> " << (ok1 ? "OK" : "FAIL")
                      << ", WriteNodeDetailsCsv -> " << (ok2 ? "OK" : "FAIL") << "\n";

            std::ofstream fout(txtSummary.string(), std::ios::out | std::ios::trunc);
            if (fout.is_open()) {
                collector->PrintSummary(fout);
                fout.close();
                std::cerr << "[WATCHDOG] Wrote summary to " << txtSummary << "\n";
            } else {
                std::cerr << "[WATCHDOG] Failed to open " << txtSummary << " for writing\n";
            }
        } catch (const std::exception &ex) {
            std::cerr << "[WATCHDOG] exception while writing outputs: " << ex.what() << "\n";
        }

        // Last resort: hard exit.
        std::_Exit(2);
    });
    watchdog.detach();

    // stop/run
    Simulator::Stop(Seconds(simDuration));
    Simulator::Run();
    run_returned.store(true); // mark that Run returned

    // normal post-run: write and exit
    std::cerr << "[SIMDBG] Simulator::Run returned at t=" << Simulator::Now().GetSeconds() << "\n";

    std::filesystem::path csvSummary = outDir / "metrics_summary.csv";
    std::filesystem::path csvDetails = outDir / "metrics_node_details.csv";
    std::filesystem::path txtSummary = outDir / "summary.txt";

    try {
        bool ok1 = collector->WriteSummaryCsv(csvSummary.string());
        bool ok2 = collector->WriteNodeDetailsCsv(csvDetails.string());
        std::cerr << "[INFO] WriteSummaryCsv -> " << (ok1 ? "OK" : "FAIL") << ", WriteNodeDetailsCsv -> " << (ok2 ? "OK" : "FAIL") << "\n";

        std::ofstream fout(txtSummary.string(), std::ios::out | std::ios::trunc);
        if (fout.is_open()) {
            collector->PrintSummary(fout);
            fout.close();
            std::cerr << "[INFO] Wrote summary text to " << txtSummary << "\n";
        } else {
            std::cerr << "[WARN] Could not open " << txtSummary << " for writing\n";
        }
    } catch (const std::exception &ex) {
        std::cerr << "[ERR] Exception while writing outputs: " << ex.what() << "\n";
    }
    std::cerr << "[INFO] Reached Here\n";

    Simulator::Destroy();
    std::cerr << "[INFO] Simulation finished. Outputs in: " << outDir << "\n";
    return 0;
}
