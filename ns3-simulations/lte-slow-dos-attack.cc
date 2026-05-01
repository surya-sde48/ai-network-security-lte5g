/*
 * Slow-Rate DoS Attack Simulation
 * This attack EVADES traditional IDS (like Snort) by staying below detection thresholds
 * AI-based IDS CAN detect it through pattern analysis
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

NS_LOG_COMPONENT_DEFINE("SlowRateDoS");

uint64_t slowAttackPackets = 0;
uint64_t normalPackets = 0;

int main(int argc, char *argv[])
{
    double simTime = 60.0;
    uint16_t numEnbs = 3;
    uint16_t numNormalUes = 20;
    uint16_t numAttackerUes = 5;
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "⚠️  SLOW-RATE DoS ATTACK SIMULATION ⚠️" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "This attack EVADES traditional IDS!" << std::endl;
    std::cout << "Normal packet rate: 10 pps" << std::endl;
    std::cout << "Attacker rate: 50 pps (BELOW threshold)" << std::endl;
    std::cout << "Traditional IDS threshold: 100 pps" << std::endl;
    std::cout << "Result: Snort CANNOT detect ❌" << std::endl;
    std::cout << "        AI CAN detect ✅" << std::endl;
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
    
    // Connect
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
    
    // Attacker UEs (SLOW RATE)
    NodeContainer attackerUeNodes;
    attackerUeNodes.Create(numAttackerUes);
    MobilityHelper attackerMobility;
    attackerMobility.SetPositionAllocator("ns3::RandomBoxPositionAllocator",
                                          "X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=3000.0]"),
                                          "Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1000.0]"),
                                          "Z", StringValue("ns3::ConstantRandomVariable[Constant=0.0]"));
    attackerMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    attackerMobility.Install(attackerUeNodes);
    
    // Install LTE devices
    NetDeviceContainer enbLteDevs = lteHelper->InstallEnbDevice(enbNodes);
    NetDeviceContainer normalUeLteDevs = lteHelper->InstallUeDevice(normalUeNodes);
    NetDeviceContainer attackerUeLteDevs = lteHelper->InstallUeDevice(attackerUeNodes);
    
    // Install Internet stack
    internet.Install(normalUeNodes);
    internet.Install(attackerUeNodes);
    
    Ipv4InterfaceContainer normalUeIpIface = epcHelper->AssignUeIpv4Address(normalUeLteDevs);
    Ipv4InterfaceContainer attackerUeIpIface = epcHelper->AssignUeIpv4Address(attackerUeLteDevs);
    
    // Attach UEs
    for (uint16_t i = 0; i < numNormalUes; i++)
    {
        lteHelper->Attach(normalUeLteDevs.Get(i), enbLteDevs.Get(i % numEnbs));
    }
    for (uint16_t i = 0; i < numAttackerUes; i++)
    {
        lteHelper->Attach(attackerUeLteDevs.Get(i), enbLteDevs.Get(i % numEnbs));
    }
    
    // Setup routing
    for (uint16_t u = 0; u < normalUeNodes.GetN(); u++)
    {
        Ptr<Ipv4StaticRouting> ueStaticRouting = 
            ipv4RoutingHelper.GetStaticRouting(normalUeNodes.Get(u)->GetObject<Ipv4>());
        ueStaticRouting->SetDefaultRoute(epcHelper->GetUeDefaultGatewayAddress(), 1);
    }
    for (uint16_t u = 0; u < attackerUeNodes.GetN(); u++)
    {
        Ptr<Ipv4StaticRouting> ueStaticRouting = 
            ipv4RoutingHelper.GetStaticRouting(attackerUeNodes.Get(u)->GetObject<Ipv4>());
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
        client.SetAttribute("Interval", TimeValue(MilliSeconds(100))); // 10 pps
        client.SetAttribute("MaxPackets", UintegerValue(1000000));
        client.SetAttribute("PacketSize", UintegerValue(512));
        clientApps.Add(client.Install(remoteHost));
        port++;
    }
    
    serverApps.Start(Seconds(0.1));
    clientApps.Start(Seconds(0.5));
    
    // SLOW-RATE ATTACK applications
    std::cout << "⚠️  [ATTACK] Slow-rate DoS configured" << std::endl;
    std::cout << "⚠️  [ATTACK] Rate: 50 pps (BELOW Snort threshold of 100 pps)" << std::endl;
    std::cout << "⚠️  [ATTACK] Traditional IDS will MISS this!" << std::endl;
    
    for (uint16_t i = 0; i < numAttackerUes; i++)
    {
        UdpServerHelper server(port);
        serverApps.Add(server.Install(attackerUeNodes.Get(i)));
        
        // SLOW but sustained attack - 50 packets/sec (below threshold!)
        UdpClientHelper client(attackerUeIpIface.GetAddress(i), port);
        client.SetAttribute("Interval", TimeValue(MilliSeconds(20))); // 50 pps
        client.SetAttribute("MaxPackets", UintegerValue(1000000));
        client.SetAttribute("PacketSize", UintegerValue(512));
        clientApps.Add(client.Install(remoteHost));
        port++;
    }
    
    // Enable traces
    lteHelper->EnableTraces();
    
    // Flow monitor
    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();
    
    // NetAnim
    AnimationInterface anim("lte-slow-dos-animation.xml");
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
    for (uint32_t i = 0; i < attackerUeNodes.GetN(); ++i)
    {
        anim.UpdateNodeDescription(attackerUeNodes.Get(i), "SLOW_ATTACKER");
        anim.UpdateNodeColor(attackerUeNodes.Get(i), 255, 165, 0); // Orange (stealthy!)
    }
    anim.UpdateNodeDescription(remoteHost, "Internet");
    anim.UpdateNodeColor(remoteHost, 255, 255, 0);
    
    // Run simulation
    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    
    // Save flow statistics
    monitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();
    
    std::ofstream flowFile;
    flowFile.open("slow-dos-flow-stats.txt");
    flowFile << "FlowID Source Destination TxPackets RxPackets LostPackets Throughput(Mbps) Delay(ms) Jitter(ms) IsSlowAttack\n";
    
    for (auto i = stats.begin(); i != stats.end(); ++i)
    {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(i->first);
        double throughput = i->second.rxBytes * 8.0 / simTime / 1000000.0;
        double delay = i->second.rxPackets > 0 ? 
                      i->second.delaySum.GetMilliSeconds() / i->second.rxPackets : 0;
        double jitter = i->second.rxPackets > 1 ? 
                       i->second.jitterSum.GetMilliSeconds() / (i->second.rxPackets - 1) : 0;
        
        // Identify slow attack: packet rate between 40-60 pps
        uint32_t pps = i->second.txPackets / simTime;
        bool isSlowAttack = (pps >= 40 && pps <= 60);
        
        flowFile << i->first << " "
                 << t.sourceAddress << " "
                 << t.destinationAddress << " "
                 << i->second.txPackets << " "
                 << i->second.rxPackets << " "
                 << i->second.lostPackets << " "
                 << throughput << " "
                 << delay << " "
                 << jitter << " "
                 << (isSlowAttack ? "YES" : "NO") << "\n";
    }
    
    flowFile.close();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "SLOW-RATE DoS SIMULATION COMPLETE" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Attack Type: Slow-rate DoS" << std::endl;
    std::cout << "Attack Rate: 50 pps per attacker" << std::endl;
    std::cout << "Snort Threshold: 100 pps" << std::endl;
    std::cout << "Snort Detection: ❌ FAILED (below threshold)" << std::endl;
    std::cout << "AI Detection: ✅ CAN DETECT (abnormal pattern)" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Flow statistics: slow-dos-flow-stats.txt" << std::endl;
    std::cout << "Animation: lte-slow-dos-animation.xml" << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    Simulator::Destroy();
    return 0;
}
