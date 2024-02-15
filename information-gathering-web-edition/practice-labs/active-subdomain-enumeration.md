# Active Subdomain Enumeration

### Submit the FQDN of the nameserver for the "inlanefreight.htb" domain as the answer.

```bash
┌──(kali㉿kali)-[~]
└─$ nslookup -type=NS inlanefreight.htb 10.129.34.225 
Server:         10.129.34.225
Address:        10.129.34.225#53

inlanefreight.htb       nameserver = ns.inlanefreight.htb.
```

ns.inlanefreight.htb

### Identify how many zones exist on the target nameserver. Submit the number of found zones as the answer.

```bash
┌──(kali㉿kali)-[~]
└─$ nslookup -type=any -query=AXFR inlanefreight.htb 10.129.34.225       
Server:         10.129.34.225
Address:        10.129.34.225#53

inlanefreight.htb
        origin = inlanefreight.htb
        mail addr = root.inlanefreight.htb
        serial = 2
        refresh = 604800
        retry = 86400
        expire = 2419200
        minimum = 604800
inlanefreight.htb       nameserver = ns.inlanefreight.htb.
Name:   admin.inlanefreight.htb
Address: 10.10.34.2
Name:   ftp.admin.inlanefreight.htb
Address: 10.10.34.2
Name:   careers.inlanefreight.htb
Address: 10.10.34.50
Name:   dc1.inlanefreight.htb
Address: 10.10.34.16
Name:   dc2.inlanefreight.htb
Address: 10.10.34.11
Name:   internal.inlanefreight.htb
Address: 127.0.0.1
Name:   admin.internal.inlanefreight.htb
Address: 10.10.1.11
Name:   wsus.internal.inlanefreight.htb
Address: 10.10.1.240
Name:   ir.inlanefreight.htb
Address: 10.10.45.5
Name:   dev.ir.inlanefreight.htb
Address: 10.10.45.6
Name:   ns.inlanefreight.htb
Address: 127.0.0.1
Name:   resources.inlanefreight.htb
Address: 10.10.34.100
Name:   securemessaging.inlanefreight.htb
Address: 10.10.34.52
Name:   test1.inlanefreight.htb
Address: 10.10.34.101
Name:   us.inlanefreight.htb
Address: 10.10.200.5
Name:   cluster14.us.inlanefreight.htb
Address: 10.10.200.14
Name:   messagecenter.us.inlanefreight.htb
Address: 10.10.200.10
Name:   ww02.inlanefreight.htb
Address: 10.10.34.112
Name:   www1.inlanefreight.htb
Address: 10.10.34.111
inlanefreight.htb
        origin = inlanefreight.htb
        mail addr = root.inlanefreight.htb
        serial = 2
        refresh = 604800
        retry = 86400
        expire = 2419200
        minimum = 604800
```

2

### Find and submit the contents of the TXT record as the answer.

```
┌──(kali㉿kali)-[~]
└─$ nslookup -type=any -query=AXFR internal.inlanefreight.htb ns.inlanefreight.htb
Server:         ns.inlanefreight.htb
Address:        10.129.34.225#53

internal.inlanefreight.htb
        origin = inlanefreight.htb
        mail addr = root.inlanefreight.htb
        serial = 2
        refresh = 604800
        retry = 86400
        expire = 2419200
        minimum = 604800
internal.inlanefreight.htb      text = "ZONE_TRANSFER{87o2z3cno7zsoiedznxoi82z3o47xzhoi}"
internal.inlanefreight.htb      nameserver = ns.inlanefreight.htb.
Name:   dev.admin.internal.inlanefreight.htb
Address: 10.10.1.2
Name:   panel.admin.internal.inlanefreight.htb
Address: 10.10.1.2
Name:   printer.admin.internal.inlanefreight.htb
Address: 10.10.1.3
Name:   dc3.internal.inlanefreight.htb
Address: 10.10.1.5
Name:   ns.internal.inlanefreight.htb
Address: 127.0.0.1
Name:   ns2.internal.inlanefreight.htb
Address: 10.10.34.136
Name:   ws1.internal.inlanefreight.htb
Address: 10.10.2.11
Name:   ws2.internal.inlanefreight.htb
Address: 10.10.3.12
internal.inlanefreight.htb
        origin = inlanefreight.htb
        mail addr = root.inlanefreight.htb
        serial = 2
        refresh = 604800
        retry = 86400
        expire = 2419200
        minimum = 604800
```

ZONE\_TRANSFER{87o2z3cno7zsoiedznxoi82z3o47xzhoi}

### What FQDN is assigned to the IP address 10.10.1.5? Submit the FQDN as the answer.

```
Name:   dc3.internal.inlanefreight.htb
Address: 10.10.1.5
```

### Which IP address is assigned to the "us.inlanefreight.htb" subdomain. Submit the IP address as the answer.

```
Name:   us.inlanefreight.htb
Address: 10.10.200.5
```

### Submit the number of all "A" records from all zones as the answer.

{% code lineNumbers="true" %}
```bash
Name:   admin.inlanefreight.htb
Name:   ftp.admin.inlanefreight.htb
Name:   careers.inlanefreight.htb
Name:   dc1.inlanefreight.htb
Name:   dc2.inlanefreight.htb
Name:   internal.inlanefreight.htb
Name:   admin.internal.inlanefreight.htb
Name:   wsus.internal.inlanefreight.htb
Name:   ir.inlanefreight.htb
Name:   dev.ir.inlanefreight.htb
Name:   ns.inlanefreight.htb
Name:   resources.inlanefreight.htb
Name:   securemessaging.inlanefreight.htb
Name:   test1.inlanefreight.htb
Name:   us.inlanefreight.htb
Name:   cluster14.us.inlanefreight.htb
Name:   messagecenter.us.inlanefreight.htb
Name:   ww02.inlanefreight.htb
Name:   www1.inlanefreight.htb
Name:   dev.admin.internal.inlanefreight.htb
Name:   panel.admin.internal.inlanefreight.htb
Name:   printer.admin.internal.inlanefreight.htb
Name:   dc3.internal.inlanefreight.htb
Name:   ns.internal.inlanefreight.htb
Name:   ns2.internal.inlanefreight.htb
Name:   ws1.internal.inlanefreight.htb
Name:   ws2.internal.inlanefreight.htb
```
{% endcode %}

27
