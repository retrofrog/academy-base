# SMTP

### Enumerate the SMTP service and submit the banner, including its version as the answer.

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap 10.129.59.197 -sC -sV -p25
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-14 10:29 EST
Nmap scan report for 10.129.59.197 (10.129.59.197)
Host is up (0.27s latency).

PORT   STATE SERVICE VERSION
25/tcp open  smtp
|_smtp-commands: mail1, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
| fingerprint-strings: 
|   Hello: 
|     220 InFreight ESMTP v2.11
|_    Syntax: EHLO hostname
```

InFreight ESMTP v2.11

### Enumerate the SMTP service even further and find the username that exists on the system. Submit it as the answer.

The thought process for this, based on our finding above we see that smtp command VRFY is allowed, so we can try to emulate users using smtp-user-enum, and dont forget to change the maximum wait timer because 5 seconds is too fast sometimes

```bash
smtp-user-enum -U ~/footprinting-wordlist.txt -t 10.129.198.161 -w 15 -v
```

robin
