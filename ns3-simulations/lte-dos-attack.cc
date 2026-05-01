/* 
 * LTE DoS Attack Simulation
 * 5G/LTE Network Security Project
 * 
 * Simulates a Denial of Service (DoS) attack where malicious nodes
 * flood the network with excessive traffic to disrupt normal operations.
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

NS_LOG_COMPONENT_DEFINE("LteDoSAttack");

uint64_t normalPacketsSent = 0;
uint64_t normalPacketsReceived = 0;
uint64_t attackPacketsSent = 0;
uint64_t totalBytesSent = 0;
uint64_t totalBytesReceived = 0;

void PacketTxCallback(std::string context, Ptr<const Packet> packet)
{
    normalPacketsSent++;
    totalBytesSent += packet->GetSize();
}

void PacketRxCallback(std::string context, Ptr<const Packet> packet, const Address &address)
{
    normalPacketsReceived++;
    totalBytesReceived += packet->GetSize();
    
    if (normalPacketsReceived % 100 == 0)
    {
        std::cout << "[TRAFFIC] Time: " << Simulator::Now().GetSeconds() 
                  << "s | Packets: " << normalPacketsReceived 
                  << " | Data: " << totalBytesReceived / 1024 << " KB" << std::endl;
    }
}

int main(int argc, char *argv[])
{
    // Simulation parameters
    double simTime = 10.0;
    uint16_t numEnbs = 3;
    uint16_t numLegitimateUe = 6;
    uint16_t numAttackerUe = 4;
    double attackStartTime = 3.0;
    double distance = 1000.0;
    
    CommandLine cmd;
    cmd.AddValue("simTime", "Simulation time", simTime);
    cmd.AddValue("numEnbs", "Number of eNodeBs", numEnbs);
    cmd.AddValue("numLegitimateUe", "Number of normal UEs", numLegitimateUe);
    cmd.AddValue("numAttackerUe", "Number of attacker UEs", numAttackerUe);
    cmd.AddValue("attackStartTime", "When DoS attack starts", attackStartTime);
    cmd.Parse(argc, argv);
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "⚠️  DoS ATTACK SIMULATION ⚠️" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Simulation Time: " << simTime << " seconds" << std::endl;
    std::cout << "eNodeBs: " << numEnbs << std::endl;
    std::cout << "Legitimate UEs: " << numLegitimateUe << std::endl;
    std::cout << "Attacker UEs: " << numAttackerUe << std::endl;
    std::cout << "Attack starts at: " << attackStartTime << "s" << std::endl;
    std::cout << "Attack Type: UDP Flood (DDoS)" << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    // Create LTE Helper
    Ptr<LteHelper> lteHelper = CreateObject<LteHelper>();
    Ptr<PointToPointEpcHelper> epcHelper = CreateObject<PointToPointEpcHelper>();
    lteHelper->SetEpcHelper(epcHelper);
    Ptr<Node> pgw = epcHelper->GetPgwNode();
    
    // Create remote host
    NodeContainer remoteHostContainer;
    remoteHostContainer.Create(1);
    Ptr<Node> remoteHost = remoteHostContainer.Get(0);
    InternetStackHelper internet;
    internet.Install(remoteHostContainer);
    
    // Connect PGW to remote host
    PointToPointHelper p2ph;
    p2ph.SetDeviceAttribute("DataRate", DataRateValue(DataRate("100Gb/s")));
    p2ph.SetDeviceAttribute("Mtu", UintegerValue(1500));
    p2ph.SetChannelAttribute("Delay", TimeValue(Seconds(0.010)));
    NetDeviceContainer internetDevices = p2ph.Install(pgw, remoteHost);
    
    Ipv4AddressHelper ipv4h;
    ipv4h.SetBase("1.0.0.0", "255.0.0.0");
    Ipv4InterfaceContainer internetIpIfaces = ipv4h.Assign(internetDevices);
    
    Ipv4StaticRoutingHelper ipv4RoutingHelper;
    Ptr<Ipv4StaticRouting> remoteHostStaticRouting = 
        ipv4RoutingHelper.GetStaticRouting(remoteHost->GetObject<Ipv4>());
    remoteHostStaticRouting->AddNetworkRouteTo(Ipv4Address("7.0.0.0"), Ipv4Mask("255.0.0.0"), 1);
    
    // Create eNodeBs
    NodeContainer enbNodes;
    enbNodes.Create(numEnbs);
    MobilityHelper enbMobility;
    Ptr<ListPositionAllocator> enbPositionAlloc = CreateObject<ListPositionAllocator>();
    for (uint16_t i = 0; i < numEnbs; i++)
    {
        enbPositionAlloc->Add(Vector(distance * i, 0, 0));
    }
    enbMobility.SetPositionAllocator(enbPositionAlloc);
    enbMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    enbMobility.Install(enbNodes);
    
    // Create legitimate UEs
    NodeContainer legitUeNodes;
    legitUeNodes.Create(numLegitimateUe);
    MobilityHelper legitUeMobility;
    legitUeMobility.SetPositionAllocator("ns3::RandomBoxPositionAllocator",
                                         "X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=3000.0]"),
                                         "Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1000.0]"),
                                         "Z", StringValue("ns3::ConstantRandomVariable[Constant=0.0]"));
    legitUeMobility.SetMobilityModel("ns3::RandomWalk2dMobilityModel",
                                     "Bounds", RectangleValue(Rectangle(0, 3000, 0, 1000)));
    legitUeMobility.Install(legitUeNodes);
    
    // Create attacker UEs
    NodeContainer attackerUeNodes;
    attackerUeNodes.Create(numAttackerUe);
    MobilityHelper attackerUeMobility;
    attackerUeMobility.SetPositionAllocator("ns3::RandomBoxPositionAllocator",
                                            "X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=3000.0]"),
                                            "Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1000.0]"),
                                            "Z", StringValue("ns3::ConstantRandomVariable[Constant=0.0]"));
    attackerUeMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    attackerUeMobility.Install(attackerUeNodes);
    
    // Install LTE devices
    NetDeviceContainer enbLteDevs = lteHelper->InstallEnbDevice(enbNodes);
    NetDeviceContainer legitUeLteDevs = lteHelper->InstallUeDevice(legitUeNodes);
    NetDeviceContainer attackerUeLteDevs = lteHelper->InstallUeDevice(attackerUeNodes);
    
    // Install Internet stack
    internet.Install(legitUeNodes);
    internet.Install(attackerUeNodes);
    
    Ipv4InterfaceContainer legitUeIpIface = epcHelper->AssignUeIpv4Address(legitUeLteDevs);
    Ipv4InterfaceContainer attackerUeIpIface = epcHelper->AssignUeIpv4Address(attackerUeLteDevs);
    
    // Attach UEs to eNodeBs
    for (uint16_t i = 0; i < numLegitimateUe; i++)
    {
        lteHelper->Attach(legitUeLteDevs.Get(i), enbLteDevs.Get(i % numEnbs));
    }
    for (uint16_t i = 0; i < numAttackerUe; i++)
    {
        lteHelper->Attach(attackerUeLteDevs.Get(i), enbLteDevs.Get(i % numEnbs));
    }
    
    // Setup routing for legitimate UEs
    for (uint16_t u = 0; u < legitUeNodes.GetN(); u++)
    {
        Ptr<Ipv4StaticRouting> ueStaticRouting = 
            ipv4RoutingHelper.GetStaticRouting(legitUeNodes.Get(u)->GetObject<Ipv4>());
        ueStaticRouting->SetDefaultRoute(epcHelper->GetUeDefaultGatewayAddress(), 1);
    }
    
    // Setup routing for attacker UEs
    for (uint16_t u = 0; u < attackerUeNodes.GetN(); u++)
    {
        Ptr<Ipv4StaticRouting> ueStaticRouting = 
            ipv4RoutingHelper.GetStaticRouting(attackerUeNodes.Get(u)->GetObject<Ipv4>());
        ueStaticRouting->SetDefaultRoute(epcHelper->GetUeDefaultGatewayAddress(), 1);
    }
    
    std::cout << "[INFO] Network configured" << std::endl;
    std::cout << "[INFO] eNodeBs: " << numEnbs << std::endl;
    std::cout << "[INFO] Legitimate UEs: " << numLegitimateUe << std::endl;
    std::cout << "[INFO] Attacker UEs: " << numAttackerUe << std::endl;
    
    // Install normal traffic applications
    uint16_t port = 1234;
    ApplicationContainer normalServerApps;
    ApplicationContainer normalClientApps;
    
    for (uint16_t i = 0; i < numLegitimateUe; i++)
    {
        UdpServerHelper server(port);
        normalServerApps.Add(server.Install(legitUeNodes.Get(i)));
        
        UdpClientHelper client(legitUeIpIface.GetAddress(i), port);
        client.SetAttribute("Interval", TimeValue(MilliSeconds(100)));
        client.SetAttribute("MaxPackets", UintegerValue(1000000));
        client.SetAttribute("PacketSize", UintegerValue(512));
        normalClientApps.Add(client.Install(remoteHost));
        port++;
    }
    
    normalServerApps.Start(Seconds(0.1));
    normalClientApps.Start(Seconds(0.5));
    
    std::cout << "[INFO] Normal traffic configured" << std::endl;
    
    // Install DoS attack applications
    ApplicationContainer attackServerApps;
    ApplicationContainer attackClientApps;
    
    for (uint16_t i = 0; i < numAttackerUe; i++)
    {
        UdpServerHelper server(port);
        attackServerApps.Add(server.Install(attackerUeNodes.Get(i)));
        
        // HIGH RATE ATTACK: 1000 packets/sec with small packets
        UdpClientHelper client(attackerUeIpIface.GetAddress(i), port);
        client.SetAttribute("Interval", TimeValue(MilliSeconds(1)));  // Very high rate!
        client.SetAttribute("MaxPackets", UintegerValue(10000000));
        client.SetAttribute("PacketSize", UintegerValue(64));  // Small packets
        attackClientApps.Add(client.Install(remoteHost));
        port++;
    }
    
    attackServerApps.Start(Seconds(attackStartTime - 0.1));
    attackClientApps.Start(Seconds(attackStartTime));
    
    std::cout << "⚠️  [ATTACK] DoS attack configured to start at " << attackStartTime << "s" << std::endl;
    std::cout << "⚠️  [ATTACK] Attack rate: 1000 packets/sec per attacker" << std::endl;
    std::cout << "⚠️  [ATTACK] Total attack rate: " << (1000 * numAttackerUe) << " pps" << std::endl;
    
    // Enable traces
    lteHelper->EnableTraces();
    std::cout << "[INFO] LTE traces enabled" << std::endl;
    
    // Flow monitor
    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();
    
    // NetAnim
    AnimationInterface anim("lte-dos-attack-animation.xml");
    anim.SetMaxPktsPerTraceFile(500000);
    
    // Color nodes
    for (uint32_t i = 0; i < enbNodes.GetN(); ++i)
    {
        anim.UpdateNodeDescription(enbNodes.Get(i), "eNodeB");
        anim.UpdateNodeColor(enbNodes.Get(i), 0, 255, 0);  // Green
        anim.UpdateNodeSize(enbNodes.Get(i)->GetId(), 10, 10);
    }
    
    for (uint32_t i = 0; i < legitUeNodes.GetN(); ++i)
    {
        anim.UpdateNodeDescription(legitUeNodes.Get(i), "Normal");
        anim.UpdateNodeColor(legitUeNodes.Get(i), 0, 0, 255);  // Blue
        anim.UpdateNodeSize(legitUeNodes.Get(i)->GetId(), 5, 5);
    }
    
    for (uint32_t i = 0; i < attackerUeNodes.GetN(); ++i)
    {
        anim.UpdateNodeDescription(attackerUeNodes.Get(i), "ATTACKER");
        anim.UpdateNodeColor(attackerUeNodes.Get(i), 255, 0, 0);  // RED
        anim.UpdateNodeSize(attackerUeNodes.Get(i)->GetId(), 8, 8);
    }
    
    anim.UpdateNodeDescription(remoteHost, "Internet");
    anim.UpdateNodeColor(remoteHost, 255, 255, 0);  // Yellow
    anim.UpdateNodeSize(remoteHost->GetId(), 15, 15);
    
    std::cout << "[INFO] NetAnim enabled - attackers shown in RED!\n" << std::endl;
    
    // Run simulation
    std::cout << "[SIMULATION] Starting..." << std::endl;
    std::cout << "[SIMULATION] First " << attackStartTime << "s: Normal traffic" << std::endl;
    std::cout << "[SIMULATION] After " << attackStartTime << "s: DoS ATTACK!\n" << std::endl;
    
    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    
    // Print statistics
    std::cout << "\n========================================" << std::endl;
    std::cout << "DoS ATTACK SIMULATION COMPLETE" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Simulation Time: " << simTime << " seconds" << std::endl;
    std::cout << "Total Packets Sent: " << normalPacketsSent << std::endl;
    std::cout << "Total Packets Received: " << normalPacketsReceived << std::endl;
    std::cout << "Delivery Ratio: " 
              << (normalPacketsSent > 0 ? (double)normalPacketsReceived / normalPacketsSent * 100 : 0) 
              << "%" << std::endl;
    std::cout << "Total Throughput: " 
              << (totalBytesReceived * 8.0 / simTime / 1000000) << " Mbps" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Save flow statistics
    monitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();
    
    std::ofstream flowFile;
    flowFile.open("dos-attack-flow-stats.txt");
    flowFile << "FlowID Source Destination TxPackets RxPackets LostPackets Throughput(Mbps) Delay(ms) Jitter(ms) IsAttack\n";
    
    for (auto i = stats.begin(); i != stats.end(); ++i)
    {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(i->first);
        double throughput = i->second.rxBytes * 8.0 / simTime / 1000000.0;
        double delay = i->second.rxPackets > 0 ? 
                      i->second.delaySum.GetMilliSeconds() / i->second.rxPackets : 0;
        double jitter = i->second.rxPackets > 1 ? 
                       i->second.jitterSum.GetMilliSeconds() / (i->second.rxPackets - 1) : 0;
        
        bool isAttack = (i->second.txPackets / simTime) > 500;
        
        flowFile << i->first << " "
                 << t.sourceAddress << " "
                 << t.destinationAddress << " "
                 << i->second.txPackets << " "
                 << i->second.rxPackets << " "
                 << i->second.lostPackets << " "
                 << throughput << " "
                 << delay << " "
                 << jitter << " "
                 << (isAttack ? "YES" : "NO") << "\n";
    }
    
    flowFile.close();
    
    std::cout << "\n[INFO] Flow statistics: dos-attack-flow-stats.txt" << std::endl;
    std::cout << "[INFO] LTE statistics: DlMacStats.txt, UlMacStats.txt, etc." << std::endl;
    std::cout << "[INFO] Animation: lte-dos-attack-animation.xml" << std::endl;
    std::cout << "\n========================================" << std::endl;
    std::cout << "Next: Use this data for ML attack detection training" << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    Simulator::Destroy();
    return 0;
}
