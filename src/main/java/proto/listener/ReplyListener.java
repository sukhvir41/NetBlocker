package proto.listener;

import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.util.MacAddress;
import proto.sender.SpoofArpReply;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;


public class ReplyListener implements Runnable, PacketListener, Closeable {


    private final PcapHandle receiveHandle;
    private final Set<InetAddress> ipsToIgnore; // list of ips to ignore like gateway or spcifed list of ips
    private final Map<InetAddress, MacAddress> ipMaps; // ip address map with their mac
    private final SpoofArpReply spoofArpReply;
    private final InetAddress spoofIpAddress; // ipAddress used to scan the network

    /**
     *
     * @param receiveHandle - pcap handle used to receive packets
     * @param ipsToIgnore - set of ips not to attack
     * @param ipMaps - map to ips and mac that need to updated with attack ips
     * @param theSpoofArpReply - to send fake arp reply packets for our fake ipa address
     * @param theSpoofIpAddress - fake ip address used to scan the network
     */

    public ReplyListener(PcapHandle receiveHandle, Set<InetAddress> ipsToIgnore, Map<InetAddress, MacAddress> ipMaps, SpoofArpReply theSpoofArpReply, InetAddress theSpoofIpAddress) {
        this.receiveHandle = receiveHandle;
        this.ipsToIgnore = ipsToIgnore;
        this.ipMaps = ipMaps;
        this.spoofArpReply = theSpoofArpReply;
        this.spoofIpAddress = theSpoofIpAddress;

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
            /*if (arp.getHeader().getOperation().equals(ArpOperation.REQUEST)) {
                MacAddress sourceMacAddress = arp.getHeader().getSrcHardwareAddr();
                InetAddress sourceIpAddress = arp.getHeader().getSrcProtocolAddr();
                if (arp.getHeader().getDstProtocolAddr().equals(spoofIpAddress)) {
                    CompletableFuture.runAsync(() -> sendSoofReply(sourceIpAddress,sourceMacAddress));
                }
                addEntry(sourceIpAddress, sourceMacAddress);
            }*/
        }


    }

    private synchronized void sendSoofReply(InetAddress sourceIpAddress,MacAddress sourceMacAddress ){
        spoofArpReply.setReceivers(sourceIpAddress, sourceMacAddress);
        spoofArpReply.run();
    }

    /**
     * takes an arp reply packet and ads the source ip and the source mac to ipMap
     *
     * @param thePacket arp packet
     */
    private void workWithArpPacket(ArpPacket thePacket) {
        InetAddress ipAddress = thePacket.getHeader().getSrcProtocolAddr();
        MacAddress macAddress = thePacket.getHeader().getSrcHardwareAddr();
        addEntry(ipAddress, macAddress);

    }

    /**
     * add the ip and mac to ipMap . It doesn't add ip mentioned in ipsToIgnore
     * @param ipAddress - ip address to add
     * @param macAddress - mac address to add
     */
    private void addEntry(InetAddress ipAddress, MacAddress macAddress) {
       // System.out.println("add entry to ip address called  --- "+  ipAddress  +"  --------   " + !ipsToIgnore.contains(ipAddress));

        /*if (!ipsToIgnore.contains(ipAddress) && !macAddress.equals(MacAddress.ETHER_BROADCAST_ADDRESS)) {
           // System.out.println("adding " + ipAddress + "   " + macAddress);
            ipMaps.put(ipAddress, macAddress);
        }*/

        if (!ipsToIgnore.contains(ipAddress)) {
            // System.out.println("adding " + ipAddress + "   " + macAddress);
            ipMaps.put(ipAddress, macAddress);
        }
    }


    @Override
    public void close() throws IOException {
        try {
            receiveHandle.breakLoop();
        } catch (NotOpenException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}
