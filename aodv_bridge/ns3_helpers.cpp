// aodv_bridge/ns3_helpers.cpp
//
// ns-3 helper utilities (updated):
//  - stronger socket-level logging for debugging packet delivery
//  - SendUdpBytes binds to the node's actual IPv4 address when possible
//  - uses Ptr<Socket> as map keys (unchanged)

#include <ns3/core-module.h>
#include <ns3/network-module.h>
#include <ns3/internet-module.h>
#include <ns3/wifi-module.h>
#include <ns3/mobility-module.h>
#include <ns3/aodv-module.h>
#include <ns3/applications-module.h>

#include <vector>
#include <map>
#include <functional>
#include <memory>
#include <iostream>
#include <sstream>

using namespace ns3;

namespace ns3bridge {

class Ns3Helper {
public:
    Ns3Helper() = default;

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

    void InstallAodvRouting() {
        if (nodes_.GetN() == 0) {
            NS_FATAL_ERROR("No nodes built; call BuildWifiNodes() first.");
        }
        InternetStackHelper internet;
        AodvHelper aodvRouting;
        internet.SetRoutingHelper(aodvRouting);
        internet.Install(nodes_);
    }

    void AssignIpv4Addresses(const std::string& base = "10.1.1.0",
                             const std::string& mask = "255.255.255.0") {
        if (devices_.GetN() == 0) {
            NS_FATAL_ERROR("No NetDevices present; build wifi nodes first.");
        }
        Ipv4AddressHelper ipv4;
        ipv4.SetBase(Ipv4Address(base.c_str()), Ipv4Mask(mask.c_str()));
        interfaces_ = ipv4.Assign(devices_);
    }

    Ipv4Address GetNodeIpv4(uint32_t nodeIndex) const {
        if (nodeIndex >= interfaces_.GetN()) return Ipv4Address("0.0.0.0");
        return interfaces_.GetAddress(nodeIndex);
    }

    Ptr<Node> GetNode(uint32_t idx) const {
        if (idx >= nodes_.GetN()) return nullptr;
        return nodes_.Get(idx);
    }

    uint32_t NodeCount() const { return nodes_.GetN(); }

    void RegisterUdpReceiver(uint32_t nodeIndex, uint16_t port,
                             std::function<void(Ipv4Address, std::vector<uint8_t>)> cb) {
        Ptr<Node> node = GetNode(nodeIndex);
        if (!node) {
            std::cerr << "RegisterUdpReceiver: invalid node index " << nodeIndex << "\n";
            return;
        }

        TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        Ptr<Socket> recvSocket = Socket::CreateSocket(node, tid);
        InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), port);
        int res = recvSocket->Bind(local);
        if (res < 0) {
            std::cerr << "[ns3bridge] warning: Bind returned " << res << " for node " << nodeIndex << " port " << port << "\n";
        }
        recvSocket->SetRecvCallback(MakeCallback(&Ns3Helper::SocketRecvCallback, this));

        socketCallbacks_[recvSocket] = cb;
        socketToNode_[recvSocket] = nodeIndex;

        std::cout << "[ns3bridge] Registered UDP receiver on node " << nodeIndex << " port " << port << " socket=" << recvSocket << "\n";
    }

    bool SendUdpBytes(uint32_t srcIndex, Ipv4Address dstIp, uint16_t dstPort,
                      const std::vector<uint8_t>& payload) {
        Ptr<Node> src = GetNode(srcIndex);
        if (!src) {
            std::cerr << "SendUdpBytes: invalid src index\n";
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
                    // explicit comparison (portable across ns-3 versions)
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
            std::cerr << "[ns3bridge] SendUdpBytes: Bind returned " << res << " for srcIndex=" << srcIndex << " (srcAddr="
                      << srcAddr << ")\n";
        }

        InetSocketAddress remote = InetSocketAddress(dstIp, dstPort);
        sock->Connect(remote);

        Ptr<Packet> p = Create<Packet>(payload.data(), payload.size());
        int sent = sock->Send(p);
        std::cout << "[ns3bridge] SendUdpBytes: node=" << srcIndex << " srcAddr=" << srcAddr
                  << " -> dst=" << dstIp << ":" << dstPort << " bytes=" << payload.size()
                  << " send_result=" << sent << "\n";

        sock->Close();
        return sent > 0;
    }

    void ScheduleSend(Time when, uint32_t srcIndex, Ipv4Address dstIp, uint16_t dstPort,
                      const std::vector<uint8_t>& payload) {
        Simulator::Schedule(when, &Ns3Helper::SendUdpBytes, this, srcIndex, dstIp, dstPort, payload);
    }

private:
    NodeContainer nodes_;
    NetDeviceContainer devices_;
    Ipv4InterfaceContainer interfaces_;

    std::map<Ptr<Socket>, std::function<void(Ipv4Address, std::vector<uint8_t>)>> socketCallbacks_;
    std::map<Ptr<Socket>, uint32_t> socketToNode_;

    void SocketRecvCallback(Ptr<Socket> socket) {
        Address from;
        Ptr<Packet> pkt;
        std::cout << "[ns3bridge] SocketRecvCallback triggered on socket=" << socket;
        if (socket && socket->GetNode()) std::cout << " node=" << socket->GetNode()->GetId();
        std::cout << "\n";

        while ((pkt = socket->RecvFrom(from))) {
            InetSocketAddress inetAddr = InetSocketAddress::ConvertFrom(from);
            Ipv4Address srcIp = inetAddr.GetIpv4();

            uint32_t pktSize = pkt->GetSize();
            std::cout << "[ns3bridge] Received packet size=" << pktSize << " bytes from " << srcIp << " on socket=" << socket << "\n";

            std::vector<uint8_t> buf(pktSize);
            pkt->CopyData(buf.data(), pktSize);

            auto it = socketCallbacks_.find(socket);
            if (it != socketCallbacks_.end()) {
                try {
                    it->second(srcIp, buf);
                } catch (const std::exception& e) {
                    std::cerr << "Receiver callback exception: " << e.what() << std::endl;
                }
            } else {
                std::cerr << "[ns3bridge] No high-level callback registered for this socket\n";
            }
        }
    }
};

} // namespace ns3bridge
