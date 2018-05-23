package proto.listner;

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


public class ReplyListners implements Runnable, PacketListener {


    private PcapHandle receiveHandle;
    private List<InetAddress> ipsToIgnore; // list of ips to ignore like gateway or spcifed list of ips
    private Map<InetAddress, MacAddress> ipMaps; // ipaddress map with their mac


    public ReplyListners(PcapHandle receiveHandle, List<InetAddress> ipsToIgnore, Map<InetAddress, MacAddress> ipMaps) {
        this.receiveHandle = receiveHandle;
        this.ipsToIgnore = ipsToIgnore;
        this.ipMaps = ipMaps;
    }

    @Override
    public void run() {
        try {
            receiveHandle.setFilter("arp", BpfProgram.BpfCompileMode.OPTIMIZE);
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
            System.out.println(ipAddress+ "     :    "+ macAddress);
        }

    }
}
