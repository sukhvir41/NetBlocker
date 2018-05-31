
<b>NetBlocker</b>

This application will help you block users internet access in your network.

You can find the application in the download folder and download it. You will be needing Java and winpcap in your machine
for this application to work

<b>Please do not use this in unauthorized networks</b>

<b>Instructions</b> :
Windows
-doanload and install winpacp from the link below
-winpcap <a href ="https://www.winpcap.org/install/" target="_blank">download</a>
-add the location Packet.dll and wpcap.dll to system environment variable in PATH variable located in system32 folder
-eg:- C:\Windows\System32\wpcap.dll; C:\Windows\System32\Packet.dll;

Linux
-install libpcap

Mac Os
-not tested

<b>libraries used</b>

Pcap4j - <a href="https://github.com/kaitoy/pcap4j"  target="_blank" >github</a>

apache commons-cli - <a href="https://github.com/apache/commons-cli" target="_blank">github</a>

<b>Usage examples</b>

java -jar NetBlocker.jar -h (help)

java -jar NetBlocker.jar -ip 192.168.1.3 -mac aa:aa:aa:aa:aa:aa -a -n 192.168.1  (allow mode)

java -jar NetBlocker.jar -ip 192.168.0.3 -mac aa:aa:aa:aa:aa:aa -b -n 192.168.0 -ips 192.168.0.5,192.168.0.8 (block mode)



