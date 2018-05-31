package proto.scanners;

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

public class ArpScanNetwork implements Runnable {

    private PcapHandle sendHandle;  // pcap handle send send packets
    private String network; // network address of the network eg. 192.168.0
    private Map<InetAddress, MacAddress> ipMap; // containing ips and mac of machines to attack
    private InetAddress ipAddress; // ip used to search the network
    private MacAddress macAddress; // mac used to search the network
    public ArpScanNetwork(PcapHandle theSendhandle, String theNetwork, Map<InetAddress, MacAddress> theIplist, InetAddress theIpAddress, MacAddress theMacaddress) {
        sendHandle = theSendhandle;
        network = theNetwork;
        ipMap = theIplist;
        ipAddress = theIpAddress;
        this.macAddress = theMacaddress;
    }


    @Override
    public void run() {
        try {
            indentifyClassAndScan();

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }


    /**
     * this method checks the class and then scans the network
     */
    private void indentifyClassAndScan() throws Exception {
        String[] array = network.split("\\.");

        for (String ipblock : array) {
            int block = Integer.parseInt(ipblock);
            if (!(block < 255)) {
                throw new IllegalArgumentException("network not valid");
            }
        }

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
            sendArpRequest(network + "." + i);
        }
    }

    /**
     * sends arp request
     * src mac address  is broadcast mac
     * src ip address is broadcast ip
     * dst mac address is broadcast mac
     * dst ip address is ip address provided as the parameter
     */
    private void sendArpRequest(String stringIpAddress) throws Exception {
        InetAddress ipAddress = InetAddress.getByName(stringIpAddress);

        ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
        arpBuilder
                .hardwareType(ArpHardwareType.ETHERNET)
                .protocolType(EtherType.IPV4)
                .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
                .operation(ArpOperation.REQUEST)
                .srcHardwareAddr(macAddress)
                .srcProtocolAddr(ipAddress)
                .dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                .dstProtocolAddr(ipAddress);

        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
        etherBuilder.dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                .srcAddr(macAddress)
                .type(EtherType.ARP)
                .payloadBuilder(arpBuilder)
                .paddingAtBuild(true);

        Packet packet = etherBuilder.build();
        sendHandle.sendPacket(packet);
    }


}
