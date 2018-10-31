package NetBlocker.listener;

import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.util.MacAddress;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Map;
import java.util.Set;


public class ArpReplyListener implements Runnable, PacketListener, Closeable {


    private final PcapHandle receiveHandle;

    // list of ips to ignore like gateway or spcifed list of ips
    private final Set<MacAddress> machinesToIgnore;

    // ip address map with their mac
    private final Map<InetAddress, MacAddress> machinesToAttack;

    //this machine Ip address
    private final InetAddress machineIpAddress;

    // machine to block for others Ip address
    private final InetAddress machineToBlock;

    /**
     * @param receiveHandle    - pcap handle used to receive packets
     * @param machinesToIgnore - set of ips not to attack
     * @param machinesToAttack - map to ips and mac that need to updated with attack ips
     */
    public ArpReplyListener(
            PcapHandle receiveHandle,
            Set<MacAddress> machinesToIgnore,
            Map<InetAddress, MacAddress> machinesToAttack,
            InetAddress machineIpAddress,
            InetAddress machineToBlock) {


        this.receiveHandle = receiveHandle;
        this.machinesToIgnore = machinesToIgnore;
        this.machinesToAttack = machinesToAttack;
        this.machineIpAddress = machineIpAddress;
        this.machineToBlock = machineToBlock;
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
                addEntry(arp);
            }
        }
    }

    /**
     * takes an arp reply packet and ads the source ip and the source mac to ipMap
     *
     * @param thePacket arp packet
     */
    private void addEntry(ArpPacket thePacket) {
        InetAddress ipAddress = thePacket.getHeader().getSrcProtocolAddr();
        MacAddress macAddress = thePacket.getHeader().getSrcHardwareAddr();

        if (!machinesToIgnore.contains(macAddress) || !machineToBlock.equals(ipAddress) || !machineIpAddress.equals(ipAddress))
            machinesToAttack.put(ipAddress, macAddress);
    }


    @Override
    public void close(){
        try {
            if (receiveHandle.isOpen())
                receiveHandle.breakLoop();
        } catch (NotOpenException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}
