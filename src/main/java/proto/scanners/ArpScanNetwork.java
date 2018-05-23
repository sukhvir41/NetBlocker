package proto.scanners;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.util.Map;

public class ScanNetwork implements Runnable {

    private PcapHandle sendHandle;  // pcap handle send send packets
    private String network; // network address of the network eg. 192.168.0
    private Map<InetAddress, MacAddress> ipMap; // containing ips and mac of machines to attack

    public ScanNetwork(PcapHandle theSendhandle, String theNetwork) {
        sendHandle = theSendhandle;
        network = theNetwork;
    }


    @Override
    public void run() {

    }


    /**
     * this method checks the class and then scans the network
     */
    private void indentifyClassAndScan() throws Exception {
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
            sendArpRequest(network + "." + i);
        }
    }


    private void sendArpRequest(String stringIpAddress) throws Exception {
        InetAddress ipAddress = InetAddress.getByName(stringIpAddress);


    }


}
