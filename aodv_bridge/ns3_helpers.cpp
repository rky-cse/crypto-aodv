// aodv_bridge/ns3_helpers.cpp
//
// ns-3 helper utilities (updated for ns-3.46+ builds that don't expose GetPointer()):
//  - keeps created sockets alive so callbacks remain valid
//  - uses raw pointer address (via ptr.operator->()) as stable map key
//  - improved debug logging
//  - small helper to prune closed sockets if desired
//
// Public API preserved: BuildWifiNodes, InstallAodvRouting,
// AssignIpv4Addresses, GetNodeIpv4, GetNode, RegisterUdpReceiver,
// SendUdpBytes, ScheduleSend.
//
// Updated: added GetDeviceContainer() accessor so callers can install
// device-level energy models (WifiRadioEnergyModelHelper).

#include <ns3/core-module.h>
#include <ns3/network-module.h>
#include <ns3/internet-module.h>
#include <ns3/wifi-module.h>
#include <ns3/mobility-module.h>
#include <ns3/aodv-module.h>
#include <ns3/applications-module.h>

#include <vector>
#include <unordered_map>
#include <map>
#include <functional>
#include <memory>
#include <iostream>
#include <sstream>
#include <mutex>

using namespace ns3;

namespace ns3bridge {

class Ns3Helper {
public:
    Ns3Helper() = default;

    // Build simple adhoc WiFi nodes and place them with a constant-position mobility.
    void BuildWifiNodes(uint32_t n) {
        nodes_.Create(n);

        WifiHelper wifi;
        wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                     "DataMode", StringValue("OfdmRate54Mbps"),
                                     "ControlMode", StringValue("OfdmRate6Mbps"));

        YansWifiPhyHelper phy;
        YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
        phy.SetChannel(channel.Create());

        WifiMacHelper mac;
        mac.SetType("ns3::AdhocWifiMac");

        NetDeviceContainer devs = wifi.Install(phy, mac, nodes_);
        devices_ = devs;

        MobilityHelper mobility;
        Ptr<ListPositionAllocator> posAlloc = CreateObject<ListPositionAllocator>();
        double spacing = 1.0;
        for (uint32_t i = 0; i < n; ++i) {
            double x = (i % 10) * spacing;
            double y = (i / 10) * spacing;
            posAlloc->Add(Vector(x, y, 10.0));
        }
        mobility.SetPositionAllocator(posAlloc);
        mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
        mobility.Install(nodes_);
    }

    // Install internet stack and AODV routing
    void InstallAodvRouting() {
        if (nodes_.GetN() == 0) {
            NS_FATAL_ERROR("No nodes built; call BuildWifiNodes() first.");
        }
        InternetStackHelper internet;
        AodvHelper aodvRouting;
        internet.SetRoutingHelper(aodvRouting);
        internet.Install(nodes_);
    }

    // Assign IPv4 addresses to the NetDevices created during BuildWifiNodes()
    void AssignIpv4Addresses(const std::string& base = "10.1.1.0",
                             const std::string& mask = "255.255.255.0") {
        if (devices_.GetN() == 0) {
            NS_FATAL_ERROR("No NetDevices present; build wifi nodes first.");
        }
        Ipv4AddressHelper ipv4;
        ipv4.SetBase(Ipv4Address(base.c_str()), Ipv4Mask(mask.c_str()));
        interfaces_ = ipv4.Assign(devices_);
    }

    // Return the IPv4 address assigned to nodeIndex (or 0.0.0.0 if none)
    Ipv4Address GetNodeIpv4(uint32_t nodeIndex) const {
        if (nodeIndex >= interfaces_.GetN()) return Ipv4Address("0.0.0.0");
        return interfaces_.GetAddress(nodeIndex);
    }

    // Return the Ptr<Node> for a given index (or nullptr)
    Ptr<Node> GetNode(uint32_t idx) const {
        if (idx >= nodes_.GetN()) return nullptr;
        return nodes_.Get(idx);
    }

    uint32_t NodeCount() const { return nodes_.GetN(); }

    // Expose the NetDeviceContainer so callers can install device-level models
    NetDeviceContainer GetDeviceContainer() const {
        return devices_;
    }

    // Optional convenience: return node id (index) owning a device index or UINT32_MAX
    uint32_t GetNodeIndexForDevice(uint32_t devIndex) const {
        if (devIndex >= devices_.GetN()) return UINT32_MAX;
        Ptr<NetDevice> d = devices_.Get(devIndex);
        if (!d) return UINT32_MAX;
        Ptr<Node> n = d->GetNode();
        return n ? n->GetId() : UINT32_MAX;
    }

    // Register a UDP receiver on nodeIndex listening at 'port'. The callback receives
    // the source Ipv4Address and payload bytes vector.
    void RegisterUdpReceiver(uint32_t nodeIndex, uint16_t port,
                             std::function<void(Ipv4Address, std::vector<uint8_t>)> cb) {
        Ptr<Node> node = GetNode(nodeIndex);
        if (!node) {
            std::cerr << "[ns3bridge] RegisterUdpReceiver: invalid node index " << nodeIndex << "\n";
            return;
        }

        TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        Ptr<Socket> recvSocket = Socket::CreateSocket(node, tid);
        InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), port);
        int res = recvSocket->Bind(local);
        if (res < 0) {
            std::cerr << "[ns3bridge] warning: Bind returned " << res << " for node " << nodeIndex
                      << " port " << port << "\n";
        }

        // keep socket alive by storing it in the sockets_ vector
        {
            std::lock_guard<std::mutex> lk(mu_);
            sockets_.push_back(recvSocket);
        }

        // use the raw pointer returned by operator->() as a stable key
        uintptr_t key = reinterpret_cast<uintptr_t>(recvSocket.operator->());
        recvSocket->SetRecvCallback(MakeCallback(&Ns3Helper::SocketRecvCallback, this));

        {
            std::lock_guard<std::mutex> lk(mu_);
            socketCallbacks_[key] = std::move(cb);
            socketToNode_[key] = nodeIndex;
        }

        std::cout << "[ns3bridge] Registered UDP receiver on node " << nodeIndex
                  << " port " << port << " socketPtr=" << reinterpret_cast<void*>(key) << "\n";
    }

    // Send raw bytes from srcIndex to dstIp:dstPort. Tries to bind the send socket to the node's
    // primary non-loopback IPv4 address when available.
    bool SendUdpBytes(uint32_t srcIndex, Ipv4Address dstIp, uint16_t dstPort,
                      const std::vector<uint8_t>& payload) {
        Ptr<Node> src = GetNode(srcIndex);
        if (!src) {
            std::cerr << "[ns3bridge] SendUdpBytes: invalid src index " << srcIndex << "\n";
            return false;
        }

        TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        Ptr<Socket> sock = Socket::CreateSocket(src, tid);

        // Try to bind to the node's first non-loopback, non-zero IPv4 address.
        Ipv4Address srcAddr = Ipv4Address::GetAny();
        Ptr<Ipv4> ipv4 = src->GetObject<Ipv4>();
        if (ipv4) {
            bool found = false;
            for (uint32_t i = 0; i < ipv4->GetNInterfaces() && !found; ++i) {
                for (uint32_t j = 0; j < ipv4->GetNAddresses(i); ++j) {
                    Ipv4InterfaceAddress ifAddr = ipv4->GetAddress(i, j);
                    Ipv4Address a = ifAddr.GetLocal();
                    if ((a != Ipv4Address("127.0.0.1")) && (a != Ipv4Address("0.0.0.0"))) {
                        srcAddr = a;
                        found = true;
                        break;
                    }
                }
            }
        }

        InetSocketAddress local = InetSocketAddress(srcAddr, 0);
        int res = sock->Bind(local);
        if (res < 0) {
            std::cerr << "[ns3bridge] SendUdpBytes: Bind returned " << res << " for srcIndex=" << srcIndex
                      << " (srcAddr=" << srcAddr << ")\n";
        }

        InetSocketAddress remote = InetSocketAddress(dstIp, dstPort);
        sock->Connect(remote);

        Ptr<Packet> p = Create<Packet>(payload.data(), payload.size());
        int sent = sock->Send(p);

        // keep the socket alive briefly by storing in sockets_; we Close() it but keep Ptr alive so ns-3 internals
        // don't free the object immediately (helps debugging / trace stability in simple scripts).
        {
            std::lock_guard<std::mutex> lk(mu_);
            sockets_.push_back(sock);
        }
        uintptr_t key = reinterpret_cast<uintptr_t>(sock.operator->());

        std::cout << "[ns3bridge] SendUdpBytes: node=" << srcIndex << " socketPtr=" << reinterpret_cast<void*>(key)
                  << " srcAddr=" << srcAddr << " -> dst=" << dstIp << ":" << dstPort
                  << " bytes=" << payload.size() << " send_result=" << sent << "\n";

        // Close socket after send (ok for simple use). Ptr is still retained in sockets_.
        sock->Close();
        return sent > 0;
    }

    // Schedule a send using ns-3's Simulator
    void ScheduleSend(Time when, uint32_t srcIndex, Ipv4Address dstIp, uint16_t dstPort,
                      const std::vector<uint8_t>& payload) {
        Simulator::Schedule(when, &Ns3Helper::SendUdpBytes, this, srcIndex, dstIp, dstPort, payload);
    }

    // Optional: prune closed sockets from the internal vector to avoid unbounded growth.
    // You can call this occasionally (e.g., after simulation end) if desired.
    void CleanupClosedSockets() {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<Ptr<Socket>> kept;
        kept.reserve(sockets_.size());
        for (auto &s : sockets_) {
            if (!s) continue;
            // Conservative heuristic: keep sockets that still have a node.
            if (s->GetNode()) {
                kept.push_back(s);
            } else {
                // drop
            }
        }
        sockets_.swap(kept);
    }

private:
    NodeContainer nodes_;
    NetDeviceContainer devices_;
    Ipv4InterfaceContainer interfaces_;

    // Keep sockets alive so their callbacks remain valid; access guarded by mu_
    std::vector<Ptr<Socket>> sockets_;
    std::unordered_map<uintptr_t, std::function<void(Ipv4Address, std::vector<uint8_t>)>> socketCallbacks_;
    std::unordered_map<uintptr_t, uint32_t> socketToNode_;
    std::mutex mu_;

    // Internal receive handler. Uses the socket pointer value as lookup key for the callback.
    void SocketRecvCallback(Ptr<Socket> socket) {
        if (!socket) {
            std::cerr << "[ns3bridge] SocketRecvCallback: null socket\n";
            return;
        }

        Address from;
        Ptr<Packet> pkt;
        uintptr_t key = reinterpret_cast<uintptr_t>(socket.operator->());
        std::cout << "[ns3bridge] SocketRecvCallback triggered on socketPtr=" << reinterpret_cast<void*>(key);
        if (socket->GetNode()) std::cout << " node=" << socket->GetNode()->GetId();
        std::cout << "\n";

        while ((pkt = socket->RecvFrom(from))) {
            InetSocketAddress inetAddr = InetSocketAddress::ConvertFrom(from);
            Ipv4Address srcIp = inetAddr.GetIpv4();

            uint32_t pktSize = pkt->GetSize();
            std::cout << "[ns3bridge] Received packet size=" << pktSize << " bytes from " << srcIp
                      << " on socketPtr=" << reinterpret_cast<void*>(key) << "\n";

            std::vector<uint8_t> buf(pktSize);
            pkt->CopyData(buf.data(), pktSize);

            std::function<void(Ipv4Address, std::vector<uint8_t>)> cb;
            {
                std::lock_guard<std::mutex> lk(mu_);
                auto it = socketCallbacks_.find(key);
                if (it != socketCallbacks_.end()) {
                    cb = it->second; // copy callback to call outside lock
                }
            }
            if (cb) {
                try {
                    cb(srcIp, buf);
                } catch (const std::exception& e) {
                    std::cerr << "[ns3bridge] Receiver callback exception: " << e.what() << std::endl;
                } catch (...) {
                    std::cerr << "[ns3bridge] Receiver callback unknown exception\n";
                }
            } else {
                std::cerr << "[ns3bridge] No high-level callback registered for socketPtr=" << reinterpret_cast<void*>(key) << "\n";
            }
        }
    }
};

} // namespace ns3bridge
