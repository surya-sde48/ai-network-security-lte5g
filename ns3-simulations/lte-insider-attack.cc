/*
 * Insider / Anomaly Attack Simulation
 * Legitimate user with malicious intent showing unusual behavior
 * Characteristics: Unusual timing, sensitive data access, abnormal patterns
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

NS_LOG_COMPONENT_DEFINE("InsiderAttack");

int main(int argc, char *argv[])
{
    double simTime = 60.0;
    uint16_t numEnbs = 3;
    uint16_t numNormalUes = 18;
    uint16_t numInsiderUes = 3;  // Insider attackers (malicious employees)
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "⚠️  INSIDER / ANOMALY ATTACK SIMULATION ⚠️" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Attack Type: Malicious Insider Behavior" << std::endl;
    std::cout << "Insiders: " << numInsiderUes << " UEs (legitimate credentials)" << std::endl;
    std::cout << "Pattern: Unusual access, data exfiltration" << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    // LTE Setup
    Ptr<LteHelper> lteHelper = CreateObject<LteHelper>();
    Ptr<PointToPointEpcHelper> epcHelper = CreateObject<PointToPointEpcHelper>();
    lteHelper->SetEpcHelper(epcHelper);
    Ptr<Node> pgw = epcHelper->GetPgwNode();
    
    // Remote host (corporate server)
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
    
    // Normal UEs (regular employees)
    NodeContainer normalUeNodes;
    normalUeNodes.Create(numNormalUes);
    MobilityHelper normalUeMobility;
    normalUeMobility.SetPositionAllocator("ns3::RandomBoxPositionAllocator",
                                          "X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=3000.0]"),
                                          "Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1000.0]"),
                                          "Z", StringValue("ns3::ConstantRandomVariable[Constant=0.0]"));
    normalUeMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    normalUeMobility.Install(normalUeNodes);
    
    // Insider UEs (malicious insiders with legitimate access)
    NodeContainer insiderUeNodes;
    insiderUeNodes.Create(numInsiderUes);
    MobilityHelper insiderMobility;
    insiderMobility.SetPositionAllocator("ns3::RandomBoxPositionAllocator",
                                         "X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=3000.0]"),
                                         "Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1000.0]"),
                                         "Z", StringValue("ns3::ConstantRandomVariable[Constant=0.0]"));
    insiderMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    insiderMobility.Install(insiderUeNodes);
    
    // Install LTE devices
    NetDeviceContainer enbLteDevs = lteHelper->InstallEnbDevice(enbNodes);
    NetDeviceContainer normalUeLteDevs = lteHelper->InstallUeDevice(normalUeNodes);
    NetDeviceContainer insiderUeLteDevs = lteHelper->InstallUeDevice(insiderUeNodes);
    
    // Install Internet stack
    internet.Install(normalUeNodes);
    internet.Install(insiderUeNodes);
    
    Ipv4InterfaceContainer normalUeIpIface = epcHelper->AssignUeIpv4Address(normalUeLteDevs);
    Ipv4InterfaceContainer insiderUeIpIface = epcHelper->AssignUeIpv4Address(insiderUeLteDevs);
    
    // Attach UEs
    for (uint16_t i = 0; i < numNormalUes; i++)
    {
        lteHelper->Attach(normalUeLteDevs.Get(i), enbLteDevs.Get(i % numEnbs));
    }
    for (uint16_t i = 0; i < numInsiderUes; i++)
    {
        lteHelper->Attach(insiderUeLteDevs.Get(i), enbLteDevs.Get(i % numEnbs));
    }
    
    // Setup routing
    for (uint16_t u = 0; u < normalUeNodes.GetN(); u++)
    {
        Ptr<Ipv4StaticRouting> ueStaticRouting = 
            ipv4RoutingHelper.GetStaticRouting(normalUeNodes.Get(u)->GetObject<Ipv4>());
        ueStaticRouting->SetDefaultRoute(epcHelper->GetUeDefaultGatewayAddress(), 1);
    }
    for (uint16_t u = 0; u < insiderUeNodes.GetN(); u++)
    {
        Ptr<Ipv4StaticRouting> ueStaticRouting = 
            ipv4RoutingHelper.GetStaticRouting(insiderUeNodes.Get(u)->GetObject<Ipv4>());
        ueStaticRouting->SetDefaultRoute(epcHelper->GetUeDefaultGatewayAddress(), 1);
    }
    
    // Normal traffic applications (business hours: 9am-5pm simulation)
    uint16_t port = 1234;
    ApplicationContainer serverApps, clientApps;
    
    for (uint16_t i = 0; i < numNormalUes; i++)
    {
        UdpServerHelper server(port);
        serverApps.Add(server.Install(normalUeNodes.Get(i)));
        
        // Normal users: Regular working hours pattern
        UdpClientHelper client(normalUeIpIface.GetAddress(i), port);
        client.SetAttribute("Interval", TimeValue(MilliSeconds(100)));  // 10 pps
        client.SetAttribute("MaxPackets", UintegerValue(1000000));
        client.SetAttribute("PacketSize", UintegerValue(512));
        clientApps.Add(client.Install(remoteHost));
        port++;
    }
    
    serverApps.Start(Seconds(0.1));
    clientApps.Start(Seconds(0.5));
    
    // INSIDER ATTACK - Unusual behavior patterns
    std::cout << "⚠️  [ATTACK] Insider threat configured" << std::endl;
    std::cout << "⚠️  [ATTACK] Pattern 1: Unusual time access (late night)" << std::endl;
    std::cout << "⚠️  [ATTACK] Pattern 2: Large data downloads (exfiltration)" << std::endl;
    std::cout << "⚠️  [ATTACK] Pattern 3: Access to sensitive resources" << std::endl;
    
    for (uint16_t insider = 0; insider < numInsiderUes; insider++)
    {
        // Pattern 1: Off-hours access (late night activity)
        // Starts later in simulation (simulating midnight access)
        UdpServerHelper server1(port);
        serverApps.Add(server1.Install(insiderUeNodes.Get(insider)));
        
        UdpClientHelper offHoursClient(insiderUeIpIface.GetAddress(insider), port);
        offHoursClient.SetAttribute("Interval", TimeValue(MilliSeconds(120)));  // 8.3 pps (slower)
        offHoursClient.SetAttribute("MaxPackets", UintegerValue(1000000));
        offHoursClient.SetAttribute("PacketSize", UintegerValue(512));
        
        ApplicationContainer offHoursApp = offHoursClient.Install(remoteHost);
        offHoursApp.Start(Seconds(45.0));  // Late start (unusual timing)
        port++;
        
        // Pattern 2: Large data download (data exfiltration)
        UdpServerHelper server2(port);
        serverApps.Add(server2.Install(insiderUeNodes.Get(insider)));
        
        UdpClientHelper exfilClient(insiderUeIpIface.GetAddress(insider), port);
        exfilClient.SetAttribute("Interval", TimeValue(MilliSeconds(50)));  // 20 pps (higher than normal)
        exfilClient.SetAttribute("MaxPackets", UintegerValue(1000000));
        exfilClient.SetAttribute("PacketSize", UintegerValue(1400));  // Large packets (max MTU)
        
        ApplicationContainer exfilApp = exfilClient.Install(remoteHost);
        exfilApp.Start(Seconds(10.0));
        exfilApp.Stop(Seconds(25.0));  // Burst download
        port++;
        
        // Pattern 3: Access to unusual/sensitive ports
        UdpServerHelper server3(port);
        serverApps.Add(server3.Install(insiderUeNodes.Get(insider)));
        
        UdpClientHelper sensitiveClient(insiderUeIpIface.GetAddress(insider), port);
        sensitiveClient.SetAttribute("Interval", TimeValue(MilliSeconds(200)));  // 5 pps
        sensitiveClient.SetAttribute("MaxPackets", UintegerValue(1000000));
        sensitiveClient.SetAttribute("PacketSize", UintegerValue(800));  // Medium packets
        
        ApplicationContainer sensitiveApp = sensitiveClient.Install(remoteHost);
        sensitiveApp.Start(Seconds(15.0));
        port++;
    }
    
    // Enable traces
    lteHelper->EnableTraces();
    
    // Flow monitor
    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();
    
    // NetAnim
    AnimationInterface anim("lte-insider-attack-animation.xml");
    anim.SetMaxPktsPerTraceFile(500000);
    
    for (uint32_t i = 0; i < enbNodes.GetN(); ++i)
    {
        anim.UpdateNodeDescription(enbNodes.Get(i), "eNodeB");
        anim.UpdateNodeColor(enbNodes.Get(i), 0, 255, 0);
    }
    for (uint32_t i = 0; i < normalUeNodes.GetN(); ++i)
    {
        anim.UpdateNodeDescription(normalUeNodes.Get(i), "Employee");
        anim.UpdateNodeColor(normalUeNodes.Get(i), 0, 0, 255);
    }
    for (uint32_t i = 0; i < insiderUeNodes.GetN(); ++i)
    {
        anim.UpdateNodeDescription(insiderUeNodes.Get(i), "INSIDER");
        anim.UpdateNodeColor(insiderUeNodes.Get(i), 128, 0, 128);  // Purple
    }
    anim.UpdateNodeDescription(remoteHost, "Corp_Server");
    anim.UpdateNodeColor(remoteHost, 255, 215, 0);
    
    // Run simulation
    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    
    // Save flow statistics
    monitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();
    
    std::ofstream flowFile;
    flowFile.open("insider-attack-flow-stats.txt");
    flowFile << "FlowID Source Destination TxPackets RxPackets LostPackets Throughput(Mbps) Delay(ms) Jitter(ms) IsInsider\n";
    
    for (auto i = stats.begin(); i != stats.end(); ++i)
    {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(i->first);
        double throughput = i->second.rxBytes * 8.0 / simTime / 1000000.0;
        double delay = i->second.rxPackets > 0 ? 
                      i->second.delaySum.GetMilliSeconds() / i->second.rxPackets : 0;
        double jitter = i->second.rxPackets > 1 ? 
                       i->second.jitterSum.GetMilliSeconds() / (i->second.rxPackets - 1) : 0;
        
        // Identify insider threat based on multiple anomaly indicators
        uint32_t avgPacketSize = i->second.rxPackets > 0 ? 
                                 i->second.rxBytes / i->second.rxPackets : 0;
        double duration = i->second.timeLastRxPacket.GetSeconds() - 
                         i->second.timeFirstTxPacket.GetSeconds();
        
        // Insider signatures:
        // 1. Large packet sizes (> 800 bytes) - data exfiltration
        // 2. High throughput (> 0.015 Mbps) - unusual data transfer
        // 3. Unusual timing (late start > 40s)
        bool isInsider = (avgPacketSize > 800 && throughput > 0.015) ||
                        (i->second.timeFirstTxPacket.GetSeconds() > 40.0) ||
                        (avgPacketSize > 1200);  // Very large packets
        
        flowFile << i->first << " "
                 << t.sourceAddress << " "
                 << t.destinationAddress << " "
                 << i->second.txPackets << " "
                 << i->second.rxPackets << " "
                 << i->second.lostPackets << " "
                 << throughput << " "
                 << delay << " "
                 << jitter << " "
                 << (isInsider ? "YES" : "NO") << "\n";
    }
    
    flowFile.close();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "INSIDER ATTACK SIMULATION COMPLETE" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Attack Pattern: Malicious insider behavior" << std::endl;
    std::cout << "Characteristics:" << std::endl;
    std::cout << "  • Unusual access timing (late night: t > 45s)" << std::endl;
    std::cout << "  • Large data transfers (1400 byte packets)" << std::endl;
    std::cout << "  • High throughput bursts (exfiltration)" << std::endl;
    std::cout << "  • Access to sensitive resources" << std::endl;
    std::cout << "  • Legitimate credentials (hard to detect)" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Detection Indicators:" << std::endl;
    std::cout << "  • Off-hours activity (unusual timing)" << std::endl;
    std::cout << "  • Abnormal data volume (exfiltration)" << std::endl;
    std::cout << "  • Unusual resource access patterns" << std::endl;
    std::cout << "  • Behavioral anomalies (ML detects)" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Flow statistics: insider-attack-flow-stats.txt" << std::endl;
    std::cout << "Animation: lte-insider-attack-animation.xml" << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    Simulator::Destroy();
    return 0;
}
