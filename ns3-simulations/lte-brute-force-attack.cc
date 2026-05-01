/*
 * Brute Force / R2L (Remote to Local) Attack Simulation
 * Attacker attempts repeated authentication/login attempts
 * Characteristics: High retry rate, same destination, failed connections
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/lte-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/netanim-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("BruteForceAttack");

int main(int argc, char *argv[])
{
    double simTime = 60.0;
    uint16_t numEnbs = 3;
    uint16_t numNormalUes = 18;
    uint16_t numBruteForceUes = 4;  // Brute force attackers
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "⚠️  BRUTE FORCE / R2L ATTACK SIMULATION ⚠️" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Attack Type: Authentication Brute Force" << std::endl;
    std::cout << "Attackers: " << numBruteForceUes << " UEs" << std::endl;
    std::cout << "Pattern: Repeated login attempts to same target" << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    // LTE Setup
    Ptr<LteHelper> lteHelper = CreateObject<LteHelper>();
    Ptr<PointToPointEpcHelper> epcHelper = CreateObject<PointToPointEpcHelper>();
    lteHelper->SetEpcHelper(epcHelper);
    Ptr<Node> pgw = epcHelper->GetPgwNode();
    
    // Remote host (authentication server)
    NodeContainer remoteHostContainer;
    remoteHostContainer.Create(1);
    Ptr<Node> remoteHost = remoteHostContainer.Get(0);
    InternetStackHelper internet;
    internet.Install(remoteHostContainer);
    
    PointToPointHelper p2ph;
    p2ph.SetDeviceAttribute("DataRate", DataRateValue(DataRate("100Gb/s")));
    p2ph.SetChannelAttribute("Delay", TimeValue(Seconds(0.010)));
    NetDeviceContainer internetDevices = p2ph.Install(pgw, remoteHost);
    
    Ipv4AddressHelper ipv4h;
    ipv4h.SetBase("1.0.0.0", "255.0.0.0");
    Ipv4InterfaceContainer internetIpIfaces = ipv4h.Assign(internetDevices);
    
    Ipv4StaticRoutingHelper ipv4RoutingHelper;
    Ptr<Ipv4StaticRouting> remoteHostStaticRouting = 
        ipv4RoutingHelper.GetStaticRouting(remoteHost->GetObject<Ipv4>());
    remoteHostStaticRouting->AddNetworkRouteTo(Ipv4Address("7.0.0.0"), Ipv4Mask("255.0.0.0"), 1);
    
    // eNodeBs
    NodeContainer enbNodes;
    enbNodes.Create(numEnbs);
    MobilityHelper enbMobility;
    Ptr<ListPositionAllocator> enbPositionAlloc = CreateObject<ListPositionAllocator>();
    for (uint16_t i = 0; i < numEnbs; i++)
    {
        enbPositionAlloc->Add(Vector(1000.0 * i, 0, 0));
    }
    enbMobility.SetPositionAllocator(enbPositionAlloc);
    enbMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    enbMobility.Install(enbNodes);
    
    // Normal UEs
    NodeContainer normalUeNodes;
    normalUeNodes.Create(numNormalUes);
    MobilityHelper normalUeMobility;
    normalUeMobility.SetPositionAllocator("ns3::RandomBoxPositionAllocator",
                                          "X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=3000.0]"),
                                          "Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1000.0]"),
                                          "Z", StringValue("ns3::ConstantRandomVariable[Constant=0.0]"));
    normalUeMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    normalUeMobility.Install(normalUeNodes);
    
    // Brute Force UEs (Attackers)
    NodeContainer bruteForceUeNodes;
    bruteForceUeNodes.Create(numBruteForceUes);
    MobilityHelper bruteForceMobility;
    bruteForceMobility.SetPositionAllocator("ns3::RandomBoxPositionAllocator",
                                            "X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=3000.0]"),
                                            "Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1000.0]"),
                                            "Z", StringValue("ns3::ConstantRandomVariable[Constant=0.0]"));
    bruteForceMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    bruteForceMobility.Install(bruteForceUeNodes);
    
    // Install LTE devices
    NetDeviceContainer enbLteDevs = lteHelper->InstallEnbDevice(enbNodes);
    NetDeviceContainer normalUeLteDevs = lteHelper->InstallUeDevice(normalUeNodes);
    NetDeviceContainer bruteForceUeLteDevs = lteHelper->InstallUeDevice(bruteForceUeNodes);
    
    // Install Internet stack
    internet.Install(normalUeNodes);
    internet.Install(bruteForceUeNodes);
    
    Ipv4InterfaceContainer normalUeIpIface = epcHelper->AssignUeIpv4Address(normalUeLteDevs);
    Ipv4InterfaceContainer bruteForceUeIpIface = epcHelper->AssignUeIpv4Address(bruteForceUeLteDevs);
    
    // Attach UEs
    for (uint16_t i = 0; i < numNormalUes; i++)
    {
        lteHelper->Attach(normalUeLteDevs.Get(i), enbLteDevs.Get(i % numEnbs));
    }
    for (uint16_t i = 0; i < numBruteForceUes; i++)
    {
        lteHelper->Attach(bruteForceUeLteDevs.Get(i), enbLteDevs.Get(i % numEnbs));
    }
    
    // Setup routing
    for (uint16_t u = 0; u < normalUeNodes.GetN(); u++)
    {
        Ptr<Ipv4StaticRouting> ueStaticRouting = 
            ipv4RoutingHelper.GetStaticRouting(normalUeNodes.Get(u)->GetObject<Ipv4>());
        ueStaticRouting->SetDefaultRoute(epcHelper->GetUeDefaultGatewayAddress(), 1);
    }
    for (uint16_t u = 0; u < bruteForceUeNodes.GetN(); u++)
    {
        Ptr<Ipv4StaticRouting> ueStaticRouting = 
            ipv4RoutingHelper.GetStaticRouting(bruteForceUeNodes.Get(u)->GetObject<Ipv4>());
        ueStaticRouting->SetDefaultRoute(epcHelper->GetUeDefaultGatewayAddress(), 1);
    }
    
    // Normal traffic applications
    uint16_t port = 1234;
    ApplicationContainer serverApps, clientApps;
    
    for (uint16_t i = 0; i < numNormalUes; i++)
    {
        UdpServerHelper server(port);
        serverApps.Add(server.Install(normalUeNodes.Get(i)));
        
        UdpClientHelper client(normalUeIpIface.GetAddress(i), port);
        client.SetAttribute("Interval", TimeValue(MilliSeconds(100)));  // 10 pps
        client.SetAttribute("MaxPackets", UintegerValue(1000000));
        client.SetAttribute("PacketSize", UintegerValue(512));
        clientApps.Add(client.Install(remoteHost));
        port++;
    }
    
    serverApps.Start(Seconds(0.1));
    clientApps.Start(Seconds(0.5));
    
    // BRUTE FORCE ATTACK - Repeated authentication attempts
    std::cout << "⚠️  [ATTACK] Brute force attack configured" << std::endl;
    std::cout << "⚠️  [ATTACK] Pattern: Repeated login attempts (50 pps)" << std::endl;
    std::cout << "⚠️  [ATTACK] Target: Authentication server (same destination)" << std::endl;
    std::cout << "⚠️  [ATTACK] Packet size: Small (256 bytes - auth requests)" << std::endl;
    
    // Authentication server ports (SSH:22, HTTP:80, etc.)
    uint16_t authPorts[] = {22, 80, 443, 3389, 21};  // Common services
    
    for (uint16_t attacker = 0; attacker < numBruteForceUes; attacker++)
    {
        // Each attacker tries multiple services
        for (uint16_t service = 0; service < 5; service++)
        {
            uint16_t authPort = authPorts[service];
            
            UdpServerHelper server(authPort + (attacker * 100));
            serverApps.Add(server.Install(bruteForceUeNodes.Get(attacker)));
            
            // Brute force: High frequency, small packets (login attempts)
            UdpClientHelper client(bruteForceUeIpIface.GetAddress(attacker), authPort + (attacker * 100));
            client.SetAttribute("Interval", TimeValue(MilliSeconds(20)));  // 50 pps (rapid attempts)
            client.SetAttribute("MaxPackets", UintegerValue(3000));  // 3000 attempts
            client.SetAttribute("PacketSize", UintegerValue(256));  // Small auth packets
            
            ApplicationContainer bruteApp = client.Install(remoteHost);
            bruteApp.Start(Seconds(5.0));  // Start attack at 5s
        }
    }
    
    // Enable traces
    lteHelper->EnableTraces();
    
    // Flow monitor
    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();
    
    // NetAnim
    AnimationInterface anim("lte-bruteforce-attack-animation.xml");
    anim.SetMaxPktsPerTraceFile(500000);
    
    for (uint32_t i = 0; i < enbNodes.GetN(); ++i)
    {
        anim.UpdateNodeDescription(enbNodes.Get(i), "eNodeB");
        anim.UpdateNodeColor(enbNodes.Get(i), 0, 255, 0);
    }
    for (uint32_t i = 0; i < normalUeNodes.GetN(); ++i)
    {
        anim.UpdateNodeDescription(normalUeNodes.Get(i), "Normal_UE");
        anim.UpdateNodeColor(normalUeNodes.Get(i), 0, 0, 255);
    }
    for (uint32_t i = 0; i < bruteForceUeNodes.GetN(); ++i)
    {
        anim.UpdateNodeDescription(bruteForceUeNodes.Get(i), "BRUTE_FORCE");
        anim.UpdateNodeColor(bruteForceUeNodes.Get(i), 139, 0, 0);  // Dark Red
    }
    anim.UpdateNodeDescription(remoteHost, "Auth_Server");
    anim.UpdateNodeColor(remoteHost, 255, 215, 0);  // Gold
    
    // Run simulation
    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    
    // Save flow statistics
    monitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();
    
    std::ofstream flowFile;
    flowFile.open("bruteforce-attack-flow-stats.txt");
    flowFile << "FlowID Source Destination TxPackets RxPackets LostPackets Throughput(Mbps) Delay(ms) Jitter(ms) IsBruteForce\n";
    
    for (auto i = stats.begin(); i != stats.end(); ++i)
    {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(i->first);
        double throughput = i->second.rxBytes * 8.0 / simTime / 1000000.0;
        double delay = i->second.rxPackets > 0 ? 
                      i->second.delaySum.GetMilliSeconds() / i->second.rxPackets : 0;
        double jitter = i->second.rxPackets > 1 ? 
                       i->second.jitterSum.GetMilliSeconds() / (i->second.rxPackets - 1) : 0;
        
        // Identify brute force: High packet rate (40-60 pps), small packets, repeated attempts
        uint32_t pps = i->second.txPackets / simTime;
        uint32_t avgPacketSize = i->second.rxPackets > 0 ? 
                                 i->second.rxBytes / i->second.rxPackets : 0;
        
        // Brute force signature: 40-60 pps, small packets (< 300 bytes), many attempts (> 2000)
        bool isBruteForce = (pps >= 40 && pps <= 60 && 
                            avgPacketSize < 300 && 
                            i->second.txPackets > 2000);
        
        flowFile << i->first << " "
                 << t.sourceAddress << " "
                 << t.destinationAddress << " "
                 << i->second.txPackets << " "
                 << i->second.rxPackets << " "
                 << i->second.lostPackets << " "
                 << throughput << " "
                 << delay << " "
                 << jitter << " "
                 << (isBruteForce ? "YES" : "NO") << "\n";
    }
    
    flowFile.close();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "BRUTE FORCE ATTACK SIMULATION COMPLETE" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Attack Pattern: Repeated authentication attempts" << std::endl;
    std::cout << "Characteristics:" << std::endl;
    std::cout << "  • Rapid login attempts (50 pps)" << std::endl;
    std::cout << "  • Small packet sizes (256 bytes - auth requests)" << std::endl;
    std::cout << "  • Same destination (authentication server)" << std::endl;
    std::cout << "  • High total attempts (3000+ per attacker)" << std::endl;
    std::cout << "  • Multiple service targets (SSH, HTTP, etc.)" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Detection Indicators:" << std::endl;
    std::cout << "  • Repeated connection attempts" << std::endl;
    std::cout << "  • Failed authentication patterns" << std::endl;
    std::cout << "  • High request rate to auth services" << std::endl;
    std::cout << "  • Suspicious timing (off-hours attacks)" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Flow statistics: bruteforce-attack-flow-stats.txt" << std::endl;
    std::cout << "Animation: lte-bruteforce-attack-animation.xml" << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    Simulator::Destroy();
    return 0;
}
