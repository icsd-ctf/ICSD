# Setup

1. Use the installation link to download the .ova file.
2. Import the image file to VMware using File -> Open
> [!WARNING]  
> The images are not supported by virtualbox. 

3. Choose a Virtual Machine name and location for the new VM.
4. The default Network Interface is configured as NAT. If not, please do so.
5. You can find IP address of the machine using arp-scan in your kali machine.
```
┌──(kali㉿kali)-[~/Captivity]
└─$ sudo arp-scan -l
[sudo] password for kali: 

Interface: eth0, type: EN10MB, MAC: 00:0c:29:ee:f4:ad, IPv4: 192.168.100.132
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.100.1   00:50:56:c0:00:08       VMware, Inc.
192.168.100.2   00:50:56:e5:ad:c6       VMware, Inc.
192.168.100.131 00:0c:29:d5:b9:3e       VMware, Inc.
192.168.100.254 00:50:56:fa:13:b9       VMware, Inc.

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.005 seconds (127.68 hosts/sec). 4 responded
                                                                                                                 
┌──(kali㉿kali)-[~/Captivity]
└─$ ssh root@192.168.100.131
root@192.168.100.131's password: 
Welcome to Ubuntu 23.04 (GNU/Linux 6.2.0-33-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

68 updates can be applied immediately.
22 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Last login: Thu Sep 28 09:13:52 2023 from 192.168.100.1
root@blitz:~# exit
logout
Connection to 192.168.100.131 closed.
```
6. If something goes wrong, use the credentials provided below to access the machine.

# Credentials
```
root:3AsaFRMwkdmBMQwuC4sr
```
