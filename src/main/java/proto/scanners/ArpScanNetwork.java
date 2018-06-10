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

public class ArpScanNetwork implements Runnable {

    private PcapHandle sendHandle;  // pcap handle send send packets
    private String network; // network address of the network eg. 192.168.0
    private InetAddress ipAddress; // ip used to search the network
    private MacAddress macAddress; // mac used to search the network

    /**
     *
     * @param theSendHandle - pcap handle used to scan the network
     * @param theNetwork -  network id  of the network eg. 192.168.1, 10 , 130.5
     * @param theIpAddress - ip address to use for scanning the network
     * @param theMacAddress - mac address to use for scanning the network
     */
    public ArpScanNetwork(PcapHandle theSendHandle, String theNetwork, InetAddress theIpAddress, MacAddress theMacAddress) {
        sendHandle = theSendHandle;
        network = theNetwork;
        ipAddress = theIpAddress;
        this.macAddress = theMacAddress;
        System.out.println("ip and mac used to scan the network");
        System.out.println( ipAddress + " ------ " + macAddress);
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
                .srcProtocolAddr(this.ipAddress)
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
