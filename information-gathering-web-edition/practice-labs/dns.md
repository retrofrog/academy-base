# DNS

### Which IP address maps to inlanefreight.com?

```bash
┌──(kali㉿kali)-[~]
└─$ dig inlanefreight.com @1.1.1.1               

; <<>> DiG 9.19.19-1-Debian <<>> inlanefreight.com @1.1.1.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 64675
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 2, ADDITIONAL: 3

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;inlanefreight.com.             IN      A

;; ANSWER SECTION:
inlanefreight.com.      300     IN      A       134.209.24.248

;; AUTHORITY SECTION:
inlanefreight.com.      60      IN      NS      ns1.inlanefreight.com.
inlanefreight.com.      60      IN      NS      ns2.inlanefreight.com.

;; ADDITIONAL SECTION:
ns1.inlanefreight.com.  300     IN      A       178.128.39.165
ns2.inlanefreight.com.  300     IN      A       206.189.119.186

;; Query time: 48 msec
;; SERVER: 1.1.1.1#53(1.1.1.1) (UDP)
;; WHEN: Thu Feb 15 10:15:57 EST 2024
;; MSG SIZE  rcvd: 130

```

134.209.24.248

### What is the first mailserver returned when querying the MX records for paypal.com?

```
┌──(kali㉿kali)-[~]
└─$ dig mx paypal.com     

; <<>> DiG 9.19.19-1-Debian <<>> mx paypal.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 57555
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 4, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; MBZ: 0x0005, udp: 4096
;; QUESTION SECTION:
;paypal.com.                    IN      MX

;; ANSWER SECTION:
paypal.com.             5       IN      MX      10 mx2.paypalcorp.com.
paypal.com.             5       IN      MX      10 mx1.paypalcorp.com.

;; AUTHORITY SECTION:
paypal.com.             5       IN      NS      pdns100.ultradns.com.
paypal.com.             5       IN      NS      ns1.p57.dynect.net.
paypal.com.             5       IN      NS      ns2.p57.dynect.net.
paypal.com.             5       IN      NS      pdns100.ultradns.net.

;; Query time: 112 msec
;; SERVER: 192.168.189.2#53(192.168.189.2) (UDP)
;; WHEN: Thu Feb 15 10:22:52 EST 2024
;; MSG SIZE  rcvd: 202

```

mx1.paypalcorp.com
