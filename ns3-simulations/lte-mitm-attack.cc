/*
 * Man-in-the-Middle (MITM) Attack Simulation
 * Attacker intercepts communication between legitimate nodes
 * Characteristics: Packet duplication, relay delays, eavesdropping
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

NS_LOG_COMPONENT_DEFINE("MITMAttack");

int main(int argc, char *argv[])
{
    double simTime = 60.0;
    uint16_t numEnbs = 3;
    uint16_t numNormalUes = 18;
    uint16_t numMitmUes = 2;  // MITM attackers
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "⚠️  MAN-IN-THE-MIDDLE ATTACK SIMULATION ⚠️" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Attack Type: Packet Interception & Relay" << std::endl;
    std::cout << "MITM Attackers: " << numMitmUes << " UEs" << std::endl;
    std::cout << "Pattern: Intercept, relay, duplicate packets" << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    // LTE Setup
    Ptr<LteHelper> lteHelper = CreateObject<LteHelper>();
    Ptr<PointToPointEpcHelper> epcHelper = CreateObject<PointToPointEpcHelper>();
    lteHelper->SetEpcHelper(epcHelper);
    Ptr<Node> pgw = epcHelper->GetPgwNode();
    
    // Remote host
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
    
    // MITM UEs (Attackers positioned between communicating parties)
    NodeContainer mitmUeNodes;
    mitmUeNodes.Create(numMitmUes);
    MobilityHelper mitmMobility;
    Ptr<ListPositionAllocator> mitmPositionAlloc = CreateObject<ListPositionAllocator>();
    // Position MITM nodes strategically in the middle
    mitmPositionAlloc->Add(Vector(1500.0, 500.0, 0));
    mitmPositionAlloc->Add(Vector(1500.0, -500.0, 0));
    mitmMobility.SetPositionAllocator(mitmPositionAlloc);
    mitmMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mitmMobility.Install(mitmUeNodes);
    
    // Install LTE devices
    NetDeviceContainer enbLteDevs = lteHelper->InstallEnbDevice(enbNodes);
    NetDeviceContainer normalUeLteDevs = lteHelper->InstallUeDevice(normalUeNodes);
    NetDeviceContainer mitmUeLteDevs = lteHelper->InstallUeDevice(mitmUeNodes);
    
    // Install Internet stack
    internet.Install(normalUeNodes);
    internet.Install(mitmUeNodes);
    
    Ipv4InterfaceContainer normalUeIpIface = epcHelper->AssignUeIpv4Address(normalUeLteDevs);
    Ipv4InterfaceContainer mitmUeIpIface = epcHelper->AssignUeIpv4Address(mitmUeLteDevs);
    
    // Attach UEs
    for (uint16_t i = 0; i < numNormalUes; i++)
    {
        lteHelper->Attach(normalUeLteDevs.Get(i), enbLteDevs.Get(i % numEnbs));
    }
    for (uint16_t i = 0; i < numMitmUes; i++)
    {
        lteHelper->Attach(mitmUeLteDevs.Get(i), enbLteDevs.Get(i % numEnbs));
    }
    
    // Setup routing
    for (uint16_t u = 0; u < normalUeNodes.GetN(); u++)
    {
        Ptr<Ipv4StaticRouting> ueStaticRouting = 
            ipv4RoutingHelper.GetStaticRouting(normalUeNodes.Get(u)->GetObject<Ipv4>());
        ueStaticRouting->SetDefaultRoute(epcHelper->GetUeDefaultGatewayAddress(), 1);
    }
    for (uint16_t u = 0; u < mitmUeNodes.GetN(); u++)
    {
        Ptr<Ipv4StaticRouting> ueStaticRouting = 
            ipv4RoutingHelper.GetStaticRouting(mitmUeNodes.Get(u)->GetObject<Ipv4>());
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
    
    // MITM ATTACK - Intercept and relay traffic
    std::cout << "⚠️  [ATTACK] MITM attack configured" << std::endl;
    std::cout << "⚠️  [ATTACK] Pattern: Packet interception and duplication" << std::endl;
    std::cout << "⚠️  [ATTACK] Attackers relay traffic with slight delay" << std::endl;
    
    // MITM attackers create duplicate traffic flows
    // They intercept (simulate by creating parallel flows)
    for (uint16_t mitm = 0; mitm < numMitmUes; mitm++)
    {
        // MITM receives from multiple sources (eavesdropping)
        for (uint16_t target = 0; target < 5; target++)  // Monitor 5 victims each
        {
            UdpServerHelper server(port);
            serverApps.Add(server.Install(mitmUeNodes.Get(mitm)));
            
            // MITM also sends traffic (relaying/injecting)
            // Slightly higher rate due to duplication
            UdpClientHelper client(mitmUeIpIface.GetAddress(mitm), port);
            client.SetAttribute("Interval", TimeValue(MilliSeconds(80)));  // 12.5 pps (slightly higher)
            client.SetAttribute("MaxPackets", UintegerValue(1000000));
            client.SetAttribute("PacketSize", UintegerValue(512));  // Same size to blend in
            
            ApplicationContainer mitmApp = client.Install(remoteHost);
            mitmApp.Start(Seconds(2.0));  // Start after normal traffic
            
            // MITM also sends to victims (injection)
            UdpClientHelper injector(normalUeIpIface.GetAddress(target), port + 100);
            injector.SetAttribute("Interval", TimeValue(MilliSeconds(150)));  // Lower rate
            injector.SetAttribute("MaxPackets", UintegerValue(1000000));
            injector.SetAttribute("PacketSize", UintegerValue(512));
            
            ApplicationContainer injApp = injector.Install(mitmUeNodes.Get(mitm));
            injApp.Start(Seconds(3.0));
            
            port++;
        }
    }
    
    // Enable traces
    lteHelper->EnableTraces();
    
    // Flow monitor
    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();
    
    // NetAnim
    AnimationInterface anim("lte-mitm-attack-animation.xml");
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
    for (uint32_t i = 0; i < mitmUeNodes.GetN(); ++i)
    {
        anim.UpdateNodeDescription(mitmUeNodes.Get(i), "MITM_ATTACKER");
        anim.UpdateNodeColor(mitmUeNodes.Get(i), 255, 140, 0);  // Orange
    }
    anim.UpdateNodeDescription(remoteHost, "Internet");
    anim.UpdateNodeColor(remoteHost, 255, 255, 0);
    
    // Run simulation
    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    
    // Save flow statistics
    // Save ML-ready dataset
std::ofstream csvFile("mitm-dataset.csv");

csvFile << "FlowID,SrcIP,DstIP,TxPackets,RxPackets,LostPackets,"
        << "Throughput,Delay,Jitter,PacketRate,AvgPacketSize,"
        << "FlowDuration,DuplicateScore,Label\n";

monitor->CheckForLostPackets();
Ptr<Ipv4FlowClassifier> classifier =
    DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());

auto stats = monitor->GetFlowStats();

// Track flows per source (for correlation)
std::map<Ipv4Address, int> flowCountPerSource;

for (auto &flow : stats)
{
    Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(flow.first);
    flowCountPerSource[t.sourceAddress]++;
}

// Compute stats
for (auto &flow : stats)
{
    Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(flow.first);

    double duration =
        (flow.second.timeLastTxPacket - flow.second.timeFirstTxPacket).GetSeconds();

    if (duration <= 0) duration = 0.001;

    double throughput = flow.second.rxBytes * 8.0 / simTime / 1e6;

    double delay = flow.second.rxPackets > 0 ?
        flow.second.delaySum.GetMilliSeconds() / flow.second.rxPackets : 0;

    double jitter = flow.second.rxPackets > 1 ?
        flow.second.jitterSum.GetMilliSeconds() / (flow.second.rxPackets - 1) : 0;

    double packetRate = flow.second.txPackets / duration;

    uint32_t avgSize = flow.second.rxPackets > 0 ?
        flow.second.rxBytes / flow.second.rxPackets : 0;

    // 🔥 NEW: Duplicate Score (simple approximation)
    double duplicateScore = 0.0;

    if (flow.second.rxPackets > 0)
    {
        duplicateScore = (double)flow.second.txPackets / flow.second.rxPackets;
    }

    // 🔥 Improved MITM Detection Logic
    int label = 0; // normal

    bool moderateRate = (packetRate > 8 && packetRate < 20);
    bool delayAnomaly = (delay > 20 && delay < 80);
    bool multiFlowSource = (flowCountPerSource[t.sourceAddress] > 3);
    bool duplication = (duplicateScore > 1.1 && duplicateScore < 2.5);

    if (moderateRate && delayAnomaly && (multiFlowSource || duplication))
    {
        label = 3; // MITM attack
    }

    csvFile << flow.first << ","
            << t.sourceAddress << ","
            << t.destinationAddress << ","
            << flow.second.txPackets << ","
            << flow.second.rxPackets << ","
            << flow.second.lostPackets << ","
            << throughput << ","
            << delay << ","
            << jitter << ","
            << packetRate << ","
            << avgSize << ","
            << duration << ","
            << duplicateScore << ","
            << label << "\n";
}

csvFile.close();

std::cout << "\n✅ ML Dataset generated: mitm-dataset.csv\n";
    std::cout << "\n========================================" << std::endl;
    
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "MITM ATTACK SIMULATION COMPLETE" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Attack Pattern: Packet interception and relay" << std::endl;
    std::cout << "Characteristics:" << std::endl;
    std::cout << "  • Traffic duplication (eavesdropping)" << std::endl;
    std::cout << "  • Moderate packet rate (12-15 pps)" << std::endl;
    std::cout << "  • Slight delay increase (relay latency)" << std::endl;
    std::cout << "  • Multiple flows from attacker" << std::endl;
    std::cout << "  • Normal packet sizes (blending in)" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Detection Indicators:" << std::endl;
    std::cout << "  • Duplicate packet patterns" << std::endl;
    std::cout << "  • Timing anomalies (relay delays)" << std::endl;
    std::cout << "  • Unexpected intermediate hops" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Flow statistics: mitm-attack-flow-stats.txt" << std::endl;
    std::cout << "Animation: lte-mitm-attack-animation.xml" << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    Simulator::Destroy();
    return 0;
}
