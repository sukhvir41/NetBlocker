package NetBlocker.Scanners;

import NetBlocker.Main;
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

public class ScanNetwork implements Runnable {

    private String network; // network address eg. 192.168.0
    private List<InetAddress> ips; // ips to attack
    private boolean allow;
    private PcapHandle sendHandle;
    private MacAddress myMacAddress;
    private InetAddress myInetAddress;
    private InetAddress gatewayAddress;

    public ScanNetwork
            (String theNetwork,
             List<InetAddress> theAttackIps,
             boolean allow,
             PcapHandle sendHandle,
             MacAddress myMacaddress,
             InetAddress myAddress,
             InetAddress gatewayAddress) {

        network = theNetwork;
        ips = theAttackIps;
        this.allow = allow;
        this.sendHandle = sendHandle;
        this.myMacAddress = myMacaddress;
        this.myInetAddress = myAddress;
        this.gatewayAddress = gatewayAddress;


    }


    @Override
    public void run() {
        try {
            if (Main.gatewayMacAddress == null) {
                sendGatewayArpRequest();
            }
            if (allow) {
                checkClassAndCall();// ips will be excluded from attack
            } else {
                for (InetAddress address : ips) { // only ips will attacked
                    sendArpRequest(address);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println(e.getMessage());
            System.exit(1);
        }
    }

    private void checkClassAndCall() throws Exception {
        String[] array = network.split("\\.");
        switch (array.length) {
            case 1:
                checkClassA(network);
                break;
            case 2:
                checkClassB(network);
                break;
            case 3:
                checkClassC(network);
                break;
            default:
                throw new IllegalArgumentException("network not valid");

        }


    }

    private void checkClassA(String network) throws Exception {
        for (int i = 1; i < 255; i++) {
            checkClassB(network + "." + "i");
        }

    }

    private void checkClassB(String network) throws Exception {
        for (int i = 1; i < 255; i++) {
            checkClassC(network + "." + "i");
        }

    }

    private void checkClassC(String network) throws Exception {
        for (int i = 1; i < 255; i++) {
            checkReachable(network + "." + i);
        }
    }

    private void checkReachable(String s) throws Exception {
        InetAddress address = InetAddress.getByName(s);
        if (!ips.contains(address)) {
            sendArpRequest(address);
        }
    }

    private void sendArpRequest(InetAddress address) throws Exception {
        ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
        arpBuilder
                .hardwareType(ArpHardwareType.ETHERNET)
                .protocolType(EtherType.IPV4)
                .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
                .operation(ArpOperation.REQUEST)
                .srcHardwareAddr(myMacAddress)
                .srcProtocolAddr(myInetAddress)
                .dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                .dstProtocolAddr(address);

        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
        etherBuilder.dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                .srcAddr(myMacAddress)
                .type(EtherType.ARP)
                .payloadBuilder(arpBuilder)
                .paddingAtBuild(true);

        Packet packet = etherBuilder.build();
        sendHandle.sendPacket(packet);
    }

    private void sendGatewayArpRequest() throws Exception {
        ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
        arpBuilder
                .hardwareType(ArpHardwareType.ETHERNET)
                .protocolType(EtherType.IPV4)
                .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
                .operation(ArpOperation.REQUEST)
                .srcHardwareAddr(myMacAddress)
                .srcProtocolAddr(myInetAddress)
                .dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                .dstProtocolAddr(gatewayAddress);

        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
        etherBuilder.dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                .srcAddr(myMacAddress)
                .type(EtherType.ARP)
                .payloadBuilder(arpBuilder)
                .paddingAtBuild(true);

        Packet packet = etherBuilder.build();
        sendHandle.sendPacket(packet);
    }
}
