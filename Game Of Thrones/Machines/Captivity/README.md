# Setup

1. Use the installation link to download the .ova file.
2. Import the image file to VMware using File -> Open 

![image](https://github.com/NotokDay/ICSD/assets/115024808/cfec5a4d-b2b7-4b50-8a19-4a653f92195e)

> [!WARNING]  
> The images are not supported by virtualbox. 

3. Choose a Virtual Machine name and location for the new VM.
4. The default Network Interface is configured as NAT. If not, please do so.
5. You can find IP address of the machine using arp-scan in your kali machine.
```
┌──(kali㉿kali)-[~/Captivity]
└─$ sudo arp-scan -l        
Interface: eth0, type: EN10MB, MAC: 00:0c:29:ee:f4:ad, IPv4: 192.168.100.132
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.100.1   00:50:56:c0:00:08       VMware, Inc.
192.168.100.2   00:50:56:e5:ad:c6       VMware, Inc.
192.168.100.130 00:0c:29:94:0e:fd       VMware, Inc.
192.168.100.254 00:50:56:fa:13:b9       VMware, Inc.

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.303 seconds (111.16 hosts/sec). 4 responded
```
7. If something goes wrong, use the credentials provided below to access the machine.

# Credentials
```
Administrator:gnE4ZqIYDxX78uPek1Xo
```
