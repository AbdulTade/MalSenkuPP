# MalSenkuPP
An advanced persistent malware chain consisting of a very modular C++ base loader, together with a chain of other malware scripts and binaries. Downloads and installs the python interpreter required for the python malware scripts to run.

# Components
* APTLoader - Stealthy base malware loader written entirely in C++. Creates entries the registry to make it boot persistent.
* DNS-Poisoner - Overwrites contents of local DNS cache and put entries of popular websites and make  them point to localhost written entirely in C++;
* RAT(Remote Access Trojan) - Essentially sets up a backdoor on the machine, that allows the attacker to send commands remotely over a network.
* PacketSniffer - Sniff packets on the wifi interface. Writes contents to randomly name .pcap file and then forward the data to the attacker. Entirely written in C++ using wpcap library the same library used by Wireshark.
* Keylogger - a python script that runs in the background and logs keys strokes to a file and forwards the file to the attacker.

# To-do
* Inject malicious driver into kernel - Disabling Microsoft driver signature enforcement by activating testsigning and then making a reboot and then injecting the driver into the kernel.
kernel driver would give the base malware more stealth my enabling it hide its activities
