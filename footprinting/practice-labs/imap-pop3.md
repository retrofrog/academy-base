# IMAP / POP3

### Figure out the exact organization name from the IMAP/POP3 service and submit it as the answer.

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap 10.129.208.73 -sV -p110,143,993,995 -sC
PORT    STATE SERVICE  VERSION
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: SASL STLS UIDL PIPELINING AUTH-RESP-CODE TOP CAPA RESP-CODES
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dev.inlanefreight.htb/organizationName=InlaneFreight Ltd/stateOrProvinceName=London/countryName=UK
| Not valid before: 2021-11-08T23:10:05
|_Not valid after:  2295-08-23T23:10:05
143/tcp open  imap     Dovecot imapd
|_ssl-date: TLS randomness does not represent time
|_imap-capabilities: IMAP4rev1 SASL-IR more LOGIN-REFERRALS LITERAL+ post-login STARTTLS OK listed ENABLE ID Pre-login LOGINDISABLEDA0001 have capabilities IDLE
| ssl-cert: Subject: commonName=dev.inlanefreight.htb/organizationName=InlaneFreight Ltd/stateOrProvinceName=London/countryName=UK
| Not valid before: 2021-11-08T23:10:05
|_Not valid after:  2295-08-23T23:10:05
993/tcp open  ssl/imap Dovecot imapd
|_imap-capabilities: SASL-IR AUTH=PLAINA0001 LOGIN-REFERRALS LITERAL+ more IDLE OK Pre-login ENABLE post-login listed IMAP4rev1 have capabilities ID
| ssl-cert: Subject: commonName=dev.inlanefreight.htb/organizationName=InlaneFreight Ltd/stateOrProvinceName=London/countryName=UK
| Not valid before: 2021-11-08T23:10:05
|_Not valid after:  2295-08-23T23:10:05
|_ssl-date: TLS randomness does not represent time
995/tcp open  ssl/pop3 Dovecot pop3d
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: SASL(PLAIN) USER UIDL PIPELINING AUTH-RESP-CODE TOP CAPA RESP-CODES
| ssl-cert: Subject: commonName=dev.inlanefreight.htb/organizationName=InlaneFreight Ltd/stateOrProvinceName=London/countryName=UK
| Not valid before: 2021-11-08T23:10:05
|_Not valid after:  2295-08-23T23:10:05
```

InlaneFreight Ltd

### What is the FQDN that the IMAP and POP3 servers are assigned to?

dev.inlanefreight.htb

### Enumerate the IMAP service and submit the flag as the answer. (Format: HTB{...})

```bash
┌──(kali㉿kali)-[~]
└─$ nc 10.129.208.73 143                            
* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS LOGINDISABLED] HTB{roncfbw7iszerd7shni7jr2343zhrj}
```

HTB{roncfbw7iszerd7shni7jr2343zhrj}

### What is the customized version of the POP3 server?

```bash
┌──(kali㉿kali)-[~]
└─$ nc 10.129.208.73 110
+OK InFreight POP3 v9.188
```

### What is the admin email address?

```bash
openssl s_client -connect 10.129.208.73:imaps
1 LOGIN robin robin
1 LIST "" *
1 SELECT DEV.DEPARTMENT.INT #resulted in * 1 EXISTS
1 FETCH 1 all
#* 1 FETCH (FLAGS (\Seen) INTERNALDATE "08-Nov-2021 23:51:24 +0000" RFC822.SIZE 167 ENVELOPE ("Wed, 03 Nov 2021 16:13:27 +0200" "Flag" (("CTO" NIL "devadmin" "inlanefreight.htb")) (("CTO" NIL "devadmin" "inlanefreight.htb")) (("CTO" NIL "devadmin" "inlanefreight.htb")) (("Robin" NIL "robin" "inlanefreight.htb")) NIL NIL NIL NIL))
```

devadmin@inlanefreight.htb

### Try to access the emails on the IMAP server and submit the flag as the answer. (Format: HTB{...})

```bash
1 FETCH 1 BODY[]
* 1 FETCH (BODY[] {167}
Subject: Flag
To: Robin <robin@inlanefreight.htb>
From: CTO <devadmin@inlanefreight.htb>
Date: Wed, 03 Nov 2021 16:13:27 +0200

HTB{983uzn8jmfgpd8jmof8c34n7zio}
```
