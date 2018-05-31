package proto.listener;

import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.util.MacAddress;
import proto.sender.SpoofArpReply;

import java.net.InetAddress;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;


public class ReplyListener implements Runnable, PacketListener {


    private PcapHandle receiveHandle;
    private Set<InetAddress> ipsToIgnore; // list of ips to ignore like gateway or spcifed list of ips
    private Map<InetAddress, MacAddress> ipMaps; // ip address map with their mac
    private SpoofArpReply spoofArpReply;

    public ReplyListener(PcapHandle receiveHandle, Set<InetAddress> ipsToIgnore, Map<InetAddress, MacAddress> ipMaps, SpoofArpReply theSpoofArpReply) {
        this.receiveHandle = receiveHandle;
        this.ipsToIgnore = ipsToIgnore;
        this.ipMaps = ipMaps;
        this.spoofArpReply = theSpoofArpReply;

    }

    @Override
    public void run() {
        try {
            receiveHandle.setFilter("arp or icmp", BpfProgram.BpfCompileMode.OPTIMIZE);
            receiveHandle.loop(-1, this);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }

    }


    @Override
    public void gotPacket(Packet packet) {
        if (packet.contains(ArpPacket.class)) {
            ArpPacket arp = packet.get(ArpPacket.class);
            if (arp.getHeader().getOperation().equals(ArpOperation.REPLY)) {
                workWithArpPacket(arp);
            } else if (arp.getHeader().getOperation().equals(ArpOperation.REQUEST)) {
                spoofArpReply.setReceivers(arp.getHeader().getSrcProtocolAddr(), arp.getHeader().getSrcHardwareAddr());
                CompletableFuture.runAsync(spoofArpReply);
            }
        }


    }

    /**
     * takes an arp reply packet
     *
     * @param thePacket arp packet
     */
    private void workWithArpPacket(ArpPacket thePacket) {
        InetAddress ipAddress = thePacket.getHeader().getSrcProtocolAddr();
        MacAddress macAddress = thePacket.getHeader().getSrcHardwareAddr();

        if (!ipsToIgnore.contains(ipAddress)) {
            ipMaps.put(ipAddress, macAddress);
        }

    }
}
