// simulations/auth_scenario.cc
//
// Updated auth scenario: writes timestamped results, records crypto timings,
// and writes CSV/text summaries at the end. Adds a simple watchdog that will
// write outputs and force-exit if the simulator doesn't finish in time.
//
// Notes: assumes helper modules exist (ns3_helpers.cpp, auth_manager.cpp,
// sodium_crypto.cpp, metrics_collector.cpp)

#include <ns3/core-module.h>
#include <ns3/network-module.h>
#include <ns3/internet-module.h>
#include <ns3/energy-module.h>

#include <iostream>
#include <memory>
#include <chrono>
#include <filesystem>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <thread>
#include <atomic>
#include <cstdlib>
#include <unistd.h> // for getcwd

#include "aodv_bridge/ns3_helpers.cpp"
#include "auth/auth_manager.cpp"
#include "crypto/sodium_crypto.cpp"
#include "metrics/metrics_collector.cpp"

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
    uint32_t nodeCount = 5; // default: {0:foreign UAV, 1..N-2 relays, N-1:BS}
    double simDuration = 10.0; // seconds
    double watchdogGrace = 5.0; // seconds beyond simDuration before forced shutdown
    std::string outBase = "results";
    cmd.AddValue("nodes", "Number of nodes (min 3)", nodeCount);
    cmd.AddValue("time", "Simulation time (s)", simDuration);
    cmd.AddValue("outdir", "Base output directory (default: results)", outBase);
    cmd.AddValue("grace", "Watchdog grace period (s) added to simDuration before forced shutdown", watchdogGrace);
    cmd.Parse(argc, argv);

    if (nodeCount < 3) nodeCount = 3;

    // timestamped output dir: results/YYYYMMDD-HHMMSS
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
    std::string runDirName = ts.str();
    std::filesystem::path outDir = basePath / runDirName;

    try {
        std::filesystem::create_directories(outDir);
    } catch (const std::exception &e) {
        std::cerr << "Failed to create output directory '" << outDir.string() << "': " << e.what() << "\n";
        return 1;
    }

    // debug: current working directory
    if (char *cwd = getcwd(nullptr, 0)) {
        std::cerr << "[DEBUG] cwd = " << cwd << "\n";
        free(cwd);
    }

    std::cout << "Outputs will be written to: " << outDir << "\n";

    // Create helpers and network
    Ns3Helper helper;
    helper.BuildWifiNodes(nodeCount);
    helper.InstallAodvRouting();
    helper.AssignIpv4Addresses("10.1.1.0", "255.255.255.0");

    // indices
    uint32_t foreignIdx = 0;
    uint32_t bsIdx = nodeCount - 1;

    Ipv4Address foreignIp = helper.GetNodeIpv4(foreignIdx);
    Ipv4Address bsIp = helper.GetNodeIpv4(bsIdx);

    std::cout << "Foreign UAV IP: " << foreignIp << "\n";
    std::cout << "BS IP: " << bsIp << "\n";

    // --- Install a BasicEnergySource on all nodes BEFORE registering nodes so
    //     initial energy is captured by MetricsCollector.RegisterNode(...)
    {
        ns3::BasicEnergySourceHelper esHelper;
        // sensible default initial energy (J). Change if needed.
        esHelper.Set("BasicEnergySourceInitialEnergyJ", DoubleValue(500.0));

        ns3::NodeContainer nc;
        for (uint32_t i = 0; i < nodeCount; ++i) {
            nc.Add(helper.GetNode(i));
        }
        esHelper.Install(nc);
        std::cerr << "[INFO] Installed BasicEnergySource on " << nodeCount << " nodes\n";

        // Optional: attach radio energy model if you have a NetDevice container available.
        // If your Ns3Helper provides GetDeviceContainer(), you can attach a WifiRadioEnergyModel
        // (uncomment and adapt when available):
        //
        // ns3::WifiRadioEnergyModelHelper radioHelper;
        // radioHelper.Set("TxCurrentA", DoubleValue(0.02));
        // radioHelper.Set("RxCurrentA", DoubleValue(0.01));
        // NetDeviceContainer devs = helper.GetDeviceContainer(); // <-- if exposed
        // radioHelper.Install(devs);
        // std::cerr << "[INFO] Installed WifiRadioEnergyModel on devices\n";
    }

    // crypto backends / auth managers
    auto crypto_uav = CreateCryptoBackend();
    auto crypto_bs  = CreateCryptoBackend();
    auto auth_uav   = CreateAuthManager(std::move(crypto_uav));
    auto auth_bs    = CreateAuthManager(std::move(crypto_bs));

    // metrics collector: register nodes AFTER energy sources installed
    auto collector = std::make_shared<MetricsCollector>();
    for (uint32_t i = 0; i < nodeCount; ++i) collector->RegisterNode(i, helper.GetNode(i));

    // Debug: print initial energy per node to confirm non-zero initial energy
    for (uint32_t i = 0; i < nodeCount; ++i) {
        Ptr<Node> n = helper.GetNode(i);
        Ptr<ns3::energy::BasicEnergySource> bes = n->GetObject<ns3::energy::BasicEnergySource>();
        if (bes) {
            std::cerr << "[DEBUG] node " << i << " initial energy = " << bes->GetRemainingEnergy() << " J\n";
        } else {
            std::cerr << "[DEBUG] node " << i << " has NO BasicEnergySource\n";
        }
    }

    // Pre-generate BS Ed25519 keypair
    auto tempCrypto = CreateCryptoBackend();
    auto bs_keys = tempCrypto->GenerateEd25519Keypair();
    if (!bs_keys.ok) {
        std::cerr << "BS key generation failed: " << bs_keys.err << "\n";
        return 1;
    }
    // split sk||pk (libsodium returns sk(64) || pk(32))
    std::vector<uint8_t> bs_sk(bs_keys.data.begin(), bs_keys.data.begin() + 64);
    std::vector<uint8_t> bs_pk(bs_keys.data.begin() + 64, bs_keys.data.end());

    // Schedule: foreign UAV generates AuthRequest at 1s
    Simulator::Schedule(Seconds(1.0), [&]() {
        auto t0 = high_resolution_clock::now();
        AuthRequest req = auth_uav->GenerateAuthRequest();
        auto t1 = high_resolution_clock::now();
        auto dur = duration_cast<microseconds>(t1 - t0).count();
        collector->AddCryptoTimeUs(foreignIdx, static_cast<uint64_t>(dur));
        collector->AddCryptoOp(foreignIdx, "AUTH_REQ_GEN", static_cast<uint64_t>(dur));

        auto wire = req.serialize();
        collector->OnPacketSent(foreignIdx, wire.size());
        bool ok = helper.SendUdpBytes(foreignIdx, bsIp, RX_PORT, wire);
        if (!ok) std::cerr << "Failed to send AuthRequest\n";
        else std::cout << "AuthRequest sent from node " << foreignIdx << " to BS\n";
    });

    // BS receiver: verify and reply
    helper.RegisterUdpReceiver(bsIdx, RX_PORT, [&](Ipv4Address from, std::vector<uint8_t> payload) {
        auto maybe = uavauth::AuthRequest::deserialize(payload);
        if (!maybe) {
            std::cerr << "BS: failed to parse AuthRequest\n";
            return;
        }
        AuthRequest req = *maybe;

        double sendTimeSec = static_cast<double>(req.timestamp) / 1000.0;
        collector->OnPacketReceived(bsIdx, payload.size(), sendTimeSec);

        auto t0 = high_resolution_clock::now();
        AuthAck ack = auth_bs->VerifyAndRespondAuthRequest(req, bs_sk, bs_pk);
        auto t1 = high_resolution_clock::now();
        auto dur = duration_cast<microseconds>(t1 - t0).count();
        collector->AddCryptoTimeUs(bsIdx, static_cast<uint64_t>(dur));
        collector->AddCryptoOp(bsIdx, "AUTH_REQ_VERIFY_AND_ACK", static_cast<uint64_t>(dur));

        // send ack back to sender on RESPONSE_PORT
        auto wire = ack.serialize();
        collector->OnPacketSent(bsIdx, wire.size());
        helper.SendUdpBytes(bsIdx, from, RESPONSE_PORT, wire);
        std::cout << "BS: AuthAck sent to " << from << "\n";
    });

    // UAV receiver: verify ack
    helper.RegisterUdpReceiver(foreignIdx, RESPONSE_PORT, [&](Ipv4Address /*from*/, std::vector<uint8_t> payload) {
        auto maybe = uavauth::AuthAck::deserialize(payload);
        if (!maybe) {
            std::cerr << "UAV: failed to parse AuthAck\n";
            return;
        }
        AuthAck ack = *maybe;

        // we don't have original sender time here; record reception with 0.0
        collector->OnPacketReceived(foreignIdx, payload.size(), 0.0);

        auto t0 = high_resolution_clock::now();
        bool ok = auth_uav->VerifyAuthAck(ack, bs_pk);
        auto t1 = high_resolution_clock::now();
        auto dur = duration_cast<microseconds>(t1 - t0).count();
        collector->AddCryptoTimeUs(foreignIdx, static_cast<uint64_t>(dur));
        collector->AddCryptoOp(foreignIdx, "AUTH_ACK_VERIFY", static_cast<uint64_t>(dur));

        if (ok) {
            std::vector<uint8_t> sess = auth_uav->GetSessionKey();
            std::cout << "UAV: Authenticated with BS successfully. Session key length = "
                      << sess.size() << " bytes\n";
        } else {
            std::cout << "UAV: Authentication with BS failed\n";
        }
    });

    // --- Watchdog: non-invasive; writes outputs & forces exit if simulator hung ---
    std::atomic<bool> sim_run_returned(false);
    std::thread watchdog([&collector, outDir, simDuration, watchdogGrace, &sim_run_returned]() {
        double waitS = simDuration + watchdogGrace;
        std::this_thread::sleep_for(std::chrono::duration<double>(waitS));
        if (sim_run_returned.load()) return; // finished normally

        std::cerr << "[WATCHDOG] timer expired (" << waitS << "s). Attempting to write outputs and exit.\n";
        try {
            std::filesystem::path csvSummary = outDir / "metrics_summary.csv";
            std::filesystem::path csvDetails = outDir / "metrics_details.csv";
            std::filesystem::path txtSummary = outDir / "summary.txt";

            bool ok1 = collector->WriteSummaryCsv(csvSummary.string());
            bool ok2 = collector->WriteNodeDetailsCsv(csvDetails.string());
            std::cerr << "[WATCHDOG] WriteSummaryCsv -> " << (ok1 ? "OK" : "FAIL") << "\n";
            std::cerr << "[WATCHDOG] WriteNodeDetailsCsv -> " << (ok2 ? "OK" : "FAIL") << "\n";

            std::ofstream fout(txtSummary.string());
            if (fout.is_open()) {
                collector->PrintSummary(fout);
                fout.close();
                std::cerr << "[WATCHDOG] Wrote summary text to: " << txtSummary << "\n";
            } else {
                int e = errno;
                std::cerr << "[WATCHDOG] Failed to open summary text file: '" << txtSummary.string()
                          << "'; errno=" << e << " (" << (e ? std::strerror(e) : "0") << ")\n";
            }
        } catch (const std::exception &ex) {
            std::cerr << "[WATCHDOG] exception while writing outputs: " << ex.what() << "\n";
        }

        // best-effort destroy and force-exit
        try { Simulator::Stop(Seconds(0.0)); } catch (...) { /*ignore*/ }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        try { Simulator::Destroy(); } catch (...) { /*ignore*/ }
        std::cerr << "[WATCHDOG] exiting process now\n";
        std::_Exit(1);
    });
    watchdog.detach();

    // run simulator
    Simulator::Stop(Seconds(simDuration));
    Simulator::Run();
    sim_run_returned.store(true);

    // normal completion: print/write outputs
    std::cerr << "[SIMDBG] Simulator::Run returned at t=" << Simulator::Now().GetSeconds() << "\n";
    collector->PrintSummary();

    std::filesystem::path csvSummary = outDir / "metrics_summary.csv";
    std::filesystem::path csvDetails = outDir / "metrics_details.csv";
    std::filesystem::path txtSummary = outDir / "summary.txt";

    // debug: print absolute paths
    try {
        std::cerr << "[DEBUG] summary csv absolute = " << std::filesystem::absolute(csvSummary).string() << "\n";
    } catch (...) { /*ignore*/ }

    bool wroteSummary = collector->WriteSummaryCsv(csvSummary.string());
    bool wroteDetails = collector->WriteNodeDetailsCsv(csvDetails.string());
    if (wroteSummary) std::cout << "Wrote CSV summary to " << csvSummary << "\n";
    else std::cerr << "Failed to write " << csvSummary << "\n";
    if (wroteDetails) std::cout << "Wrote CSV details to " << csvDetails << "\n";
    else std::cerr << "Failed to write " << csvDetails << "\n";

    std::ofstream fout(txtSummary.string());
    if (fout.is_open()) {
        collector->PrintSummary(fout);
        fout.close();
        std::cout << "Wrote summary text to: " << txtSummary << "\n";
    } else {
        std::cerr << "Failed to open summary text file: " << txtSummary << "\n";
    }

    Simulator::Destroy();
    std::cout << "Simulation finished. Outputs in: " << outDir << "\n";
    return 0;
}
