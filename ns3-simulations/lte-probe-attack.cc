/*
 * Improved Probe/Scanning Attack Simulation (ML-ready)
 * Enhancements:
 *  - Randomized scanning behavior
 *  - Better feature extraction
 *  - Multi-class labeling
 *  - Realistic normal traffic variation
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/lte-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/flow-monitor-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("ImprovedProbeAttack");

int main(int argc, char *argv[])
{
    double simTime = 60.0;
    uint16_t numEnbs = 3;
    uint16_t numNormalUes = 20;
    uint16_t numScannerUes = 3;

    srand(time(0));

    std::cout << "\n=== IMPROVED PROBE ATTACK SIMULATION ===\n";

    // LTE + EPC
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
    p2ph.SetChannelAttribute("Delay", TimeValue(Seconds(0.01)));
    NetDeviceContainer internetDevices = p2ph.Install(pgw, remoteHost);

    Ipv4AddressHelper ipv4h;
    ipv4h.SetBase("1.0.0.0", "255.0.0.0");
    Ipv4InterfaceContainer internetIpIfaces = ipv4h.Assign(internetDevices);

    // Routing
    Ipv4StaticRoutingHelper routingHelper;
    Ptr<Ipv4StaticRouting> remoteHostRouting =
        routingHelper.GetStaticRouting(remoteHost->GetObject<Ipv4>());
    remoteHostRouting->AddNetworkRouteTo("7.0.0.0", "255.0.0.0", 1);

    // eNodeBs
    NodeContainer enbNodes;
    enbNodes.Create(numEnbs);

    MobilityHelper enbMobility;
    enbMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    enbMobility.Install(enbNodes);

    // UEs
    NodeContainer normalUeNodes, scannerUeNodes;
    normalUeNodes.Create(numNormalUes);
    scannerUeNodes.Create(numScannerUes);

    MobilityHelper ueMobility;
    ueMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    ueMobility.Install(normalUeNodes);
    ueMobility.Install(scannerUeNodes);

    // Devices
    NetDeviceContainer enbDevs = lteHelper->InstallEnbDevice(enbNodes);
    NetDeviceContainer normalUeDevs = lteHelper->InstallUeDevice(normalUeNodes);
    NetDeviceContainer scannerUeDevs = lteHelper->InstallUeDevice(scannerUeNodes);

    internet.Install(normalUeNodes);
    internet.Install(scannerUeNodes);

    Ipv4InterfaceContainer normalIp = epcHelper->AssignUeIpv4Address(normalUeDevs);
    Ipv4InterfaceContainer scannerIp = epcHelper->AssignUeIpv4Address(scannerUeDevs);

    // Attach
    for (uint16_t i = 0; i < numNormalUes; i++)
        lteHelper->Attach(normalUeDevs.Get(i), enbDevs.Get(i % numEnbs));

    for (uint16_t i = 0; i < numScannerUes; i++)
        lteHelper->Attach(scannerUeDevs.Get(i), enbDevs.Get(i % numEnbs));

    // Routing
    for (uint32_t i = 0; i < normalUeNodes.GetN(); i++)
    {
        Ptr<Ipv4StaticRouting> ueRoute =
            routingHelper.GetStaticRouting(normalUeNodes.Get(i)->GetObject<Ipv4>());
        ueRoute->SetDefaultRoute(epcHelper->GetUeDefaultGatewayAddress(), 1);
    }

    for (uint32_t i = 0; i < scannerUeNodes.GetN(); i++)
    {
        Ptr<Ipv4StaticRouting> ueRoute =
            routingHelper.GetStaticRouting(scannerUeNodes.Get(i)->GetObject<Ipv4>());
        ueRoute->SetDefaultRoute(epcHelper->GetUeDefaultGatewayAddress(), 1);
    }

    // NORMAL TRAFFIC (randomized)
    uint16_t port = 2000;
    ApplicationContainer serverApps, clientApps;

    for (uint16_t i = 0; i < numNormalUes; i++)
    {
        UdpServerHelper server(port);
        serverApps.Add(server.Install(normalUeNodes.Get(i)));

        UdpClientHelper client(normalIp.GetAddress(i), port);
        client.SetAttribute("Interval",
            TimeValue(MilliSeconds(80 + rand() % 40))); // random interval
        client.SetAttribute("PacketSize",
            UintegerValue(400 + rand() % 200));

        clientApps.Add(client.Install(remoteHost));
        port++;
    }

    serverApps.Start(Seconds(0.1));
    clientApps.Start(Seconds(0.5));

    // PROBE ATTACK (IMPROVED)
    for (uint16_t s = 0; s < numScannerUes; s++)
    {
        for (uint16_t scan = 0; scan < 60; scan++)
        {
            uint16_t scanPort = 1000 + rand() % 60000;

            UdpServerHelper server(scanPort);
            serverApps.Add(server.Install(scannerUeNodes.Get(s)));

            UdpClientHelper client(scannerIp.GetAddress(s), scanPort);
            client.SetAttribute("Interval", TimeValue(MilliSeconds(5 + rand() % 10)));
            client.SetAttribute("MaxPackets", UintegerValue(30 + rand() % 40));
            client.SetAttribute("PacketSize", UintegerValue(40 + rand() % 40));

            ApplicationContainer app = client.Install(remoteHost);

            double start = 5.0 + ((double)rand() / RAND_MAX);
            app.Start(Seconds(start));
            app.Stop(Seconds(start + 0.5));
        }
    }

    // Flow Monitor
    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    // OUTPUT DATASET
    std::ofstream file("improved-probe-dataset.csv");

    file << "FlowID,TxPackets,RxPackets,LostPackets,Throughput,Delay,Jitter,Duration,PacketRate,AvgPacketSize,Label\n";

    monitor->CheckForLostPackets();
    auto stats = monitor->GetFlowStats();

    for (auto &flow : stats)
    {
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

        // Improved detection logic
        int label = 0; // normal

        if (avgSize < 100 && packetRate > 50 && duration < 1.0)
            label = 2; // probe

        file << flow.first << ","
             << flow.second.txPackets << ","
             << flow.second.rxPackets << ","
             << flow.second.lostPackets << ","
             << throughput << ","
             << delay << ","
             << jitter << ","
             << duration << ","
             << packetRate << ","
             << avgSize << ","
             << label << "\n";
    }

    file.close();

    std::cout << "\n✅ Dataset generated: improved-probe-dataset.csv\n";

    Simulator::Destroy();
    return 0;
}
