/* 
 * LTE Normal Traffic Simulation
 * Project: 5G/LTE Network Security with ML-based Attack Detection
 * 
 * This simulation creates a baseline LTE network with normal traffic patterns.
 * Data collected will be used as "normal" samples for ML training.
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/lte-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/config-store-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/netanim-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("LteNormalTraffic");

// Global variables for statistics
uint64_t totalPacketsSent = 0;
uint64_t totalPacketsReceived = 0;
uint64_t totalBytesSent = 0;
uint64_t totalBytesReceived = 0;

// Callback function when packet is sent
void TxCallback(std::string context, Ptr<const Packet> packet)
{
    totalPacketsSent++;
    totalBytesSent += packet->GetSize();
}

// Callback function when packet is received
void RxCallback(std::string context, Ptr<const Packet> packet, const Address &address)
{
    totalPacketsReceived++;
    totalBytesReceived += packet->GetSize();
    
    // Print every 100th packet to show activity
    if (totalPacketsReceived % 100 == 0)
    {
        std::cout << "[NORMAL TRAFFIC] Time: " << Simulator::Now().GetSeconds() 
                  << "s | Packets Received: " << totalPacketsReceived 
                  << " | Total Data: " << totalBytesReceived / 1024 << " KB" << std::endl;
    }
}

int main(int argc, char *argv[])
{
    // ============================================
    // SIMULATION PARAMETERS (You can modify these)
    // ============================================
    
    double simTime = 10.0;              // Simulation time in seconds
    uint16_t numEnbs = 3;               // Number of eNodeBs (cell towers)
    uint16_t numUes = 10;               // Number of UEs (mobile devices)
    double distance = 1000.0;           // Distance between eNodeBs in meters
    bool enableTraces = true;           // Enable detailed trace files
    bool enableNetAnim = true;          // Enable NetAnim visualization
    
    // Parse command line arguments
    CommandLine cmd;
    cmd.AddValue("simTime", "Total simulation time", simTime);
    cmd.AddValue("numEnbs", "Number of eNodeBs", numEnbs);
    cmd.AddValue("numUes", "Number of UEs", numUes);
    cmd.AddValue("enableTraces", "Enable trace files", enableTraces);
    cmd.AddValue("enableNetAnim", "Enable NetAnim", enableNetAnim);
    cmd.Parse(argc, argv);
    
    // ============================================
    // PRINT SIMULATION CONFIGURATION
    // ============================================
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "LTE NORMAL TRAFFIC SIMULATION" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Simulation Time: " << simTime << " seconds" << std::endl;
    std::cout << "Number of eNodeBs: " << numEnbs << std::endl;
    std::cout << "Number of UEs: " << numUes << std::endl;
    std::cout << "Network Type: LTE (4G)" << std::endl;
    std::cout << "Traffic Type: NORMAL (Baseline)" << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    // ============================================
    // CREATE LTE HELPER
    // ============================================
    
    Ptr<LteHelper> lteHelper = CreateObject<LteHelper>();
    Ptr<PointToPointEpcHelper> epcHelper = CreateObject<PointToPointEpcHelper>();
    lteHelper->SetEpcHelper(epcHelper);
    
    // Get the PGW (Packet Gateway) node
    Ptr<Node> pgw = epcHelper->GetPgwNode();
    
    // ============================================
    // CREATE REMOTE HOST (Internet Server)
    // ============================================
    
    NodeContainer remoteHostContainer;
    remoteHostContainer.Create(1);
    Ptr<Node> remoteHost = remoteHostContainer.Get(0);
    
    InternetStackHelper internet;
    internet.Install(remoteHostContainer);
    
    // Create connection between PGW and Remote Host
    PointToPointHelper p2ph;
    p2ph.SetDeviceAttribute("DataRate", DataRateValue(DataRate("100Gb/s")));
    p2ph.SetDeviceAttribute("Mtu", UintegerValue(1500));
    p2ph.SetChannelAttribute("Delay", TimeValue(Seconds(0.010)));
    
    NetDeviceContainer internetDevices = p2ph.Install(pgw, remoteHost);
    
    Ipv4AddressHelper ipv4h;
    ipv4h.SetBase("1.0.0.0", "255.0.0.0");
    Ipv4InterfaceContainer internetIpIfaces = ipv4h.Assign(internetDevices);
    
    Ipv4Address remoteHostAddr = internetIpIfaces.GetAddress(1);
    
    // Setup routing
    Ipv4StaticRoutingHelper ipv4RoutingHelper;
    Ptr<Ipv4StaticRouting> remoteHostStaticRouting = 
        ipv4RoutingHelper.GetStaticRouting(remoteHost->GetObject<Ipv4>());
    remoteHostStaticRouting->AddNetworkRouteTo(Ipv4Address("7.0.0.0"), Ipv4Mask("255.0.0.0"), 1);
    
    // ============================================
    // CREATE eNodeBs (BASE STATIONS)
    // ============================================
    
    NodeContainer enbNodes;
    enbNodes.Create(numEnbs);
    
    // Position eNodeBs in a line
    MobilityHelper enbMobility;
    Ptr<ListPositionAllocator> enbPositionAlloc = CreateObject<ListPositionAllocator>();
    
    for (uint16_t i = 0; i < numEnbs; i++)
    {
        enbPositionAlloc->Add(Vector(distance * i, 0, 0));
    }
    
    enbMobility.SetPositionAllocator(enbPositionAlloc);
    enbMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    enbMobility.Install(enbNodes);
    
    // ============================================
    // CREATE UEs (MOBILE DEVICES)
    // ============================================
    
    NodeContainer ueNodes;
    ueNodes.Create(numUes);
    
    // Position UEs randomly around eNodeBs
    MobilityHelper ueMobility;
    ueMobility.SetPositionAllocator("ns3::RandomBoxPositionAllocator",
                                     "X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=3000.0]"),
                                     "Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1000.0]"),
                                     "Z", StringValue("ns3::ConstantRandomVariable[Constant=0.0]"));
    
    // UEs can move (simulating mobile users)
    ueMobility.SetMobilityModel("ns3::RandomWalk2dMobilityModel",
                                 "Bounds", RectangleValue(Rectangle(0, 3000, 0, 1000)),
                                 "Speed", StringValue("ns3::UniformRandomVariable[Min=1.0|Max=5.0]"));
    ueMobility.Install(ueNodes);
    
    // ============================================
    // INSTALL LTE DEVICES
    // ============================================
    
    NetDeviceContainer enbLteDevs = lteHelper->InstallEnbDevice(enbNodes);
    NetDeviceContainer ueLteDevs = lteHelper->InstallUeDevice(ueNodes);
    
    // Install Internet stack on UEs
    internet.Install(ueNodes);
    Ipv4InterfaceContainer ueIpIface;
    ueIpIface = epcHelper->AssignUeIpv4Address(NetDeviceContainer(ueLteDevs));
    
    // Attach UEs to eNodeBs
    for (uint16_t i = 0; i < numUes; i++)
    {
        lteHelper->Attach(ueLteDevs.Get(i), enbLteDevs.Get(i % numEnbs));
    }
    
    // Setup IP routes for UEs
    for (uint16_t u = 0; u < ueNodes.GetN(); u++)
    {
        Ptr<Node> ueNode = ueNodes.Get(u);
        Ptr<Ipv4StaticRouting> ueStaticRouting = 
            ipv4RoutingHelper.GetStaticRouting(ueNode->GetObject<Ipv4>());
        ueStaticRouting->SetDefaultRoute(epcHelper->GetUeDefaultGatewayAddress(), 1);
    }
    
    std::cout << "[INFO] LTE Network Setup Complete!" << std::endl;
    std::cout << "[INFO] eNodeBs installed: " << numEnbs << std::endl;
    std::cout << "[INFO] UEs attached: " << numUes << std::endl;
    
    // ============================================
    // INSTALL APPLICATIONS (TRAFFIC GENERATION)
    // ============================================
    
    uint16_t dlPort = 1234;
    uint16_t ulPort = 2000;
    
    ApplicationContainer clientApps;
    ApplicationContainer serverApps;
    
    // Install UDP application (Video streaming simulation)
    // Half of the UEs will use UDP
    for (uint16_t i = 0; i < numUes / 2; i++)
    {
        // UDP Server on remote host
        UdpServerHelper dlPacketSinkHelper(dlPort);
        serverApps.Add(dlPacketSinkHelper.Install(ueNodes.Get(i)));
        
        // UDP Client on UE
        UdpClientHelper dlClient(ueIpIface.GetAddress(i), dlPort);
        dlClient.SetAttribute("Interval", TimeValue(MilliSeconds(10)));
        dlClient.SetAttribute("MaxPackets", UintegerValue(1000000));
        dlClient.SetAttribute("PacketSize", UintegerValue(1024));
        clientApps.Add(dlClient.Install(remoteHost));
        
        dlPort++;
    }
    
    // Install TCP application (Web browsing simulation)
    // Other half will use TCP
    for (uint16_t i = numUes / 2; i < numUes; i++)
    {
        // TCP Server on remote host
        PacketSinkHelper dlPacketSinkHelper("ns3::TcpSocketFactory",
                                            InetSocketAddress(Ipv4Address::GetAny(), dlPort));
        serverApps.Add(dlPacketSinkHelper.Install(ueNodes.Get(i)));
        
        // TCP Client on UE
        OnOffHelper dlClient("ns3::TcpSocketFactory",
                            InetSocketAddress(ueIpIface.GetAddress(i), dlPort));
        dlClient.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        dlClient.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
        dlClient.SetAttribute("DataRate", DataRateValue(DataRate("1Mbps")));
        dlClient.SetAttribute("PacketSize", UintegerValue(1024));
        clientApps.Add(dlClient.Install(remoteHost));
        
        dlPort++;
    }
    
    // Start applications
    serverApps.Start(Seconds(0.01));
    clientApps.Start(Seconds(0.5));
    
    std::cout << "[INFO] Traffic Generation Started!" << std::endl;
    std::cout << "[INFO] UDP clients: " << numUes / 2 << " (Video streaming)" << std::endl;
    std::cout << "[INFO] TCP clients: " << numUes / 2 << " (Web browsing)" << std::endl;
    
    // ============================================
    // ENABLE TRACES AND STATISTICS
    // ============================================
    
    if (enableTraces)
    {
        lteHelper->EnableTraces();
        std::cout << "[INFO] LTE Traces Enabled (Statistics files will be generated)" << std::endl;
    }
    
    // Connect callbacks for packet monitoring
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::UdpClient/Tx", 
                    MakeCallback(&TxCallback));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::OnOffApplication/Tx", 
                    MakeCallback(&TxCallback));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::PacketSink/Rx", 
                    MakeCallback(&RxCallback));
    
    // Enable Flow Monitor (for detailed statistics)
    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();
    
    // ============================================
    // ENABLE NetAnim (VISUALIZATION)
    // ============================================
    
    AnimationInterface *anim = nullptr;
    if (enableNetAnim)
    {
        anim = new AnimationInterface("lte-normal-traffic-animation.xml");
        anim->SetMaxPktsPerTraceFile(500000);
        
        // Set node descriptions for better visualization
        for (uint32_t i = 0; i < enbNodes.GetN(); ++i)
        {
            anim->UpdateNodeDescription(enbNodes.Get(i), "eNodeB");
            anim->UpdateNodeColor(enbNodes.Get(i), 0, 255, 0); // Green for eNodeBs
            anim->UpdateNodeSize(enbNodes.Get(i)->GetId(), 10, 10);
        }
        
        for (uint32_t i = 0; i < ueNodes.GetN(); ++i)
        {
            anim->UpdateNodeDescription(ueNodes.Get(i), "UE");
            anim->UpdateNodeColor(ueNodes.Get(i), 0, 0, 255); // Blue for UEs
            anim->UpdateNodeSize(ueNodes.Get(i)->GetId(), 5, 5);
        }
        
        anim->UpdateNodeDescription(remoteHost, "Internet");
        anim->UpdateNodeColor(remoteHost, 255, 0, 0); // Red for Internet server
        anim->UpdateNodeSize(remoteHost->GetId(), 15, 15);
        
        std::cout << "[INFO] NetAnim enabled - Animation file will be created!" << std::endl;
    }
    
    // ============================================
    // RUN SIMULATION
    // ============================================
    
    std::cout << "\n[SIMULATION] Starting simulation for " << simTime << " seconds..." << std::endl;
    std::cout << "[SIMULATION] Generating NORMAL traffic patterns...\n" << std::endl;
    
    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    
    // ============================================
    // PRINT FINAL STATISTICS
    // ============================================
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "SIMULATION COMPLETE - NORMAL TRAFFIC" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Total Simulation Time: " << simTime << " seconds" << std::endl;
    std::cout << "Total Packets Sent: " << totalPacketsSent << std::endl;
    std::cout << "Total Packets Received: " << totalPacketsReceived << std::endl;
    std::cout << "Packet Delivery Ratio: " 
              << (totalPacketsSent > 0 ? (double)totalPacketsReceived / totalPacketsSent * 100 : 0) 
              << "%" << std::endl;
    std::cout << "Total Data Sent: " << totalBytesSent / 1024 / 1024 << " MB" << std::endl;
    std::cout << "Total Data Received: " << totalBytesReceived / 1024 / 1024 << " MB" << std::endl;
    std::cout << "Average Throughput: " 
              << (totalBytesReceived * 8.0 / simTime / 1000000) << " Mbps" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Flow Monitor Statistics
    monitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();
    
    // Save detailed flow statistics to file
    std::ofstream flowStatsFile;
    flowStatsFile.open("normal-traffic-flow-stats.txt");
    flowStatsFile << "Flow_ID Source Destination Tx_Packets Rx_Packets Lost_Packets Throughput(Mbps) Delay(ms) Jitter(ms)\n";
    
    double totalDelay = 0;
    uint32_t flowCount = 0;
    
    for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin(); i != stats.end(); ++i)
    {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(i->first);
        
        double throughput = i->second.rxBytes * 8.0 / simTime / 1000000.0;
        double delay = i->second.rxPackets > 0 ? 
                      i->second.delaySum.GetMilliSeconds() / i->second.rxPackets : 0;
        double jitter = i->second.rxPackets > 1 ? 
                       i->second.jitterSum.GetMilliSeconds() / (i->second.rxPackets - 1) : 0;
        
        flowStatsFile << i->first << " "
                     << t.sourceAddress << " "
                     << t.destinationAddress << " "
                     << i->second.txPackets << " "
                     << i->second.rxPackets << " "
                     << i->second.lostPackets << " "
                     << throughput << " "
                     << delay << " "
                     << jitter << "\n";
        
        totalDelay += delay;
        flowCount++;
    }
    
    flowStatsFile.close();
    
    std::cout << "\n[INFO] Detailed flow statistics saved to: normal-traffic-flow-stats.txt" << std::endl;
    std::cout << "[INFO] Average End-to-End Delay: " 
              << (flowCount > 0 ? totalDelay / flowCount : 0) << " ms" << std::endl;
    
    if (enableTraces)
    {
        std::cout << "\n[INFO] LTE Statistics files generated:" << std::endl;
        std::cout << "  - DlMacStats.txt" << std::endl;
        std::cout << "  - DlPdcpStats.txt" << std::endl;
        std::cout << "  - DlRlcStats.txt" << std::endl;
        std::cout << "  - DlRsrpSinrStats.txt" << std::endl;
        std::cout << "  - UlMacStats.txt" << std::endl;
        std::cout << "  - UlPdcpStats.txt" << std::endl;
        std::cout << "  - UlRlcStats.txt" << std::endl;
    }
    
    if (enableNetAnim)
    {
        std::cout << "\n[INFO] NetAnim visualization file: lte-normal-traffic-animation.xml" << std::endl;
        std::cout << "[INFO] Open this file in NetAnim to see the network animation!" << std::endl;
    }
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "Next Step: Use this data as NORMAL baseline for ML training" << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    // Cleanup
    if (anim != nullptr)
    {
        delete anim;
    }
    
    Simulator::Destroy();
    return 0;
}
