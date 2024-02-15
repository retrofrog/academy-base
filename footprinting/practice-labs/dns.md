# DNS

### Interact with the target DNS using its IP address and enumerate the FQDN of it for the "inlanefreight.htb" domain.

```bash
┌──(kali㉿kali)-[~]
└─$ dig ns inlanefreight.htb @10.129.42.195

; <<>> DiG 9.19.19-1-Debian <<>> ns inlanefreight.htb @10.129.42.195
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 19067
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 2
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: a8167cbd18df33310100000065ccd4b4faa25f7db42cab6c (good)
;; QUESTION SECTION:
;inlanefreight.htb.             IN      NS

;; ANSWER SECTION:
inlanefreight.htb.      604800  IN      NS      ns.inlanefreight.htb.

;; ADDITIONAL SECTION:
ns.inlanefreight.htb.   604800  IN      A       127.0.0.1

;; Query time: 2608 msec
;; SERVER: 10.129.42.195#53(10.129.42.195) (UDP)
;; WHEN: Wed Feb 14 09:56:51 EST 2024
;; MSG SIZE  rcvd: 107
```

ns.inlanefreight.htb

### Identify if its possible to perform a zone transfer and submit the TXT record as the answer. (Format: HTB{...))

```bash
┌──(kali㉿kali)-[~]
└─$ dig axfr inlanefreight.htb @10.129.42.195                                                                                                   
; <<>> DiG 9.19.19-1-Debian <<>> axfr inlanefreight.htb @10.129.42.195
;; global options: +cmd
inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
inlanefreight.htb.      604800  IN      TXT     "MS=ms97310371"
inlanefreight.htb.      604800  IN      TXT     "atlassian-domain-verification=t1rKCy68JFszSdCKVpw64A1QksWdXuYFUeSXKU"
inlanefreight.htb.      604800  IN      TXT     "v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.124.8 ip4:10.129.127.2 ip4:10.129.42.106 ~all"
inlanefreight.htb.      604800  IN      NS      ns.inlanefreight.htb.
app.inlanefreight.htb.  604800  IN      A       10.129.18.15
dev.inlanefreight.htb.  604800  IN      A       10.12.0.1
internal.inlanefreight.htb. 604800 IN   A       10.129.1.6
mail1.inlanefreight.htb. 604800 IN      A       10.129.18.201
ns.inlanefreight.htb.   604800  IN      A       127.0.0.1
inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
;; Query time: 275 msec
;; SERVER: 10.129.42.195#53(10.129.42.195) (TCP)
;; WHEN: Wed Feb 14 09:58:47 EST 2024
;; XFR size: 11 records (messages 1, bytes 560)
```

and then we manually trying each subdomains till we found the flag

```bash
┌──(kali㉿kali)-[~]
└─$ dig axfr internal.inlanefreight.htb @10.129.42.195
; <<>> DiG 9.19.19-1-Debian <<>> axfr internal.inlanefreight.htb @10.129.42.195
;; global options: +cmd
internal.inlanefreight.htb. 604800 IN   SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
internal.inlanefreight.htb. 604800 IN   TXT     "MS=ms97310371"
internal.inlanefreight.htb. 604800 IN   TXT     "HTB{DN5_z0N3_7r4N5F3r_iskdufhcnlu34}"
internal.inlanefreight.htb. 604800 IN   TXT     "atlassian-domain-verification=t1rKCy68JFszSdCKVpw64A1QksWdXuYFUeSXKU"
internal.inlanefreight.htb. 604800 IN   TXT     "v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.124.8 ip4:10.129.127.2 ip4:10.129.42.106 ~all"
internal.inlanefreight.htb. 604800 IN   NS      ns.inlanefreight.htb.
dc1.internal.inlanefreight.htb. 604800 IN A     10.129.34.16
dc2.internal.inlanefreight.htb. 604800 IN A     10.129.34.11
mail1.internal.inlanefreight.htb. 604800 IN A   10.129.18.200
ns.internal.inlanefreight.htb. 604800 IN A      127.0.0.1
vpn.internal.inlanefreight.htb. 604800 IN A     10.129.1.6
ws1.internal.inlanefreight.htb. 604800 IN A     10.129.1.34
ws2.internal.inlanefreight.htb. 604800 IN A     10.129.1.35
wsus.internal.inlanefreight.htb. 604800 IN A    10.129.18.2
internal.inlanefreight.htb. 604800 IN   SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
;; Query time: 275 msec
;; SERVER: 10.129.42.195#53(10.129.42.195) (TCP)
;; WHEN: Wed Feb 14 10:01:04 EST 2024
;; XFR size: 15 records (messages 1, bytes 677)

```

HTB{DN5\_z0N3\_7r4N5F3r\_iskdufhcnlu34}

### What is the IPv4 address of the hostname DC1?

10.129.34.16

### What is the FQDN of the host where the last octet ends with "x.x.x.203"?

The thought process for this are there are subdomain inside a subdomain, so after we try brute on main inlanefreight.htb and didnt found the one, go try to brute force the subdomains as well, hope this makes sense :)

```bash
┌──(kali㉿kali)-[~]
└─$ for sub in $(cat /usr/share/wordlists/seclists/Discovery/DNS/fierce-hostlist.txt);do dig $sub.dev.inlanefreight.htb @10.129.42.195 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
dev1.dev.inlanefreight.htb. 604800 IN   A       10.12.3.6
ns.dev.inlanefreight.htb. 604800 IN     A       127.0.0.1
win2k.dev.inlanefreight.htb. 604800 IN  A       10.12.3.203
```

win2k.dev.inlanefreight.htb
