
<h1>NetBlocker</h1>

This application will help you block machines on the network to communicate with a specific machine in your network.

You can find the application in the download folder and download it. You will be needing Java and winpcap in your machine
for this application to work

<h3>Please do not use this in unauthorized networks</h3>

<h2>Instructions</h2>

<b>Windows</b>
<ul>
<li>doanload and install winpacp from the link below</li>
<li>winpcap <a href ="https://www.winpcap.org/install/" target="_blank">download</a></li>
<li>add the location Packet.dll and wpcap.dll to system environment variable in PATH variable located in system32 folder</li>
<li>eg:- C:\Windows\System32\wpcap.dll; C:\Windows\System32\Packet.dll;</li>
</ul>

<b>Linux</b>
<ul>
<li>install libpcap</li>
</ul>

<b>libraries used</b>

Pcap4j - <a href="https://github.com/kaitoy/pcap4j"  target="_blank" >github</a>

apache commons-cli - <a href="https://github.com/apache/commons-cli" target="_blank">github</a>

<b>Usage examples</b>

java -jar NetBlocker.jar -h (help)



