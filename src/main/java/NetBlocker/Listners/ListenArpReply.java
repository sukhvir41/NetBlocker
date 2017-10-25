package NetBlocker.Listners;

import NetBlocker.Main;
import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.util.List;
import java.util.Map;

public class ListenArpReply implements Runnable {

    private List<InetAddress> ips;
    private Map<InetAddress, MacAddress> ipMap;
    private PcapHandle receiveHandle;
    private boolean allow;

    public ListenArpReply(List<InetAddress> ips, Map<InetAddress, MacAddress> ipMap, PcapHandle receiveHandle, boolean allow) {
        this.ips = ips;
        this.ipMap = ipMap;
        this.receiveHandle = receiveHandle;
        this.allow = allow;
    }


    @Override
    public void run() {
        try {
            receiveHandle.setFilter("arp", BpfProgram.BpfCompileMode.OPTIMIZE);
            receiveHandle.loop(-1, listener);
        } catch (Exception e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }
    }


    private PacketListener listener = new PacketListener() {
        @Override
        public void gotPacket(Packet packet) {
            if (packet.contains(ArpPacket.class)) {
                ArpPacket arp = packet.get(ArpPacket.class);
                if (arp.getHeader().getOperation().equals(ArpOperation.REPLY)) {

                    if (Main.gatewayMacAddress == null && arp.getHeader().getSrcProtocolAddr().equals(Main.gatewayAddress)) {
                        Main.gatewayMacAddress = arp.getHeader().getSrcHardwareAddr();
                    }

                    if (allow) {
                        if (!ips.contains(arp.getHeader().getSrcProtocolAddr())) { // ips to exclude from attack
                            InetAddress address = arp.getHeader().getSrcProtocolAddr();
                            MacAddress macAddress = arp.getHeader().getSrcHardwareAddr();
                            ipMap.put(address, macAddress);
                        }
                    } else { // ips to attack
                        if (ips.contains(arp.getHeader().getSrcProtocolAddr())) {
                            InetAddress address = arp.getHeader().getSrcProtocolAddr();
                            MacAddress macAddress = arp.getHeader().getSrcHardwareAddr();
                            ipMap.put(address, macAddress);
                        }
                    }
                }
            }
        }
    };
}
