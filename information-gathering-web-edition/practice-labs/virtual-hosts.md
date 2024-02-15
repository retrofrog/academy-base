# Virtual Hosts

vHosts needed for these questions:

* `www.inlanefreight.htb`

### Enumerate the target and find a vHost that contains flag No. 1. Submit the flag value as your answer (in the format HTB{DATA}).

```bash
┌──(kali㉿kali)-[~]
└─$ curl -s http://inlanefreight.htb
<!doctype html>
<head>FLAG No.1:</head>
<body>
        HTB{h8973hrpiusnzjoie7zrou23i4zhmsxi8732zjso}
</body>
```

### Enumerate the target and find a vHost that contains flag No. 2. Submit the flag value as your answer (in the format HTB{DATA}).

```bash
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt -u http://inlanefreight.htb -H "HOST: FUZZ.inlanefreight.htb" -fw 3499
ap                      [Status: 200, Size: 102, Words: 3, Lines: 6, Duration: 261ms]
app                     [Status: 200, Size: 103, Words: 3, Lines: 6, Duration: 264ms]
citrix                  [Status: 200, Size: 100, Words: 3, Lines: 6, Duration: 299ms]
customers               [Status: 200, Size: 94, Words: 3, Lines: 6, Duration: 260ms]
dmz                     [Status: 200, Size: 95, Words: 2, Lines: 6, Duration: 261ms]

┌──(kali㉿kali)-[~]
└─$  curl -s http://inlanefreight.htb -H "Host: app.inlanefreight.htb"
<!doctype html>
<head>FLAG No.2:</head>
<body>
        HTB{u23i4zhmsxi872z3rn98h7nh2sxnbgriusd32zjso}
</body>
```

### Enumerate the target and find a vHost that contains flag No. 3. Submit the flag value as your answer (in the format HTB{DATA}).

```bash
┌──(kali㉿kali)-[~]
└─$  curl -s http://inlanefreight.htb -H "Host: citrix.inlanefreight.htb"
<!doctype html>
<head>FLAG No.3:</head>
<body>
        HTB{Fl4gF0uR_o8763tznb4xou7zhgsniud7gfi734}
</body>
```

### Enumerate the target and find a vHost that contains flag No. 4. Submit the flag value as your answer (in the format HTB{DATA}).

```bash
┌──(kali㉿kali)-[~]
└─$  curl -s http://inlanefreight.htb -H "Host: customers.inlanefreight.htb"
<!doctype html>
<head>FLAG No.4:</head>
<body>
        HTB{bzghi7tghin2u76x3ghdni62higz7x3s}
</body>
```

### Find the specific vHost that starts with the letter "d" and submit the flag value as your answer (in the format HTB{DATA}).

```bash
┌──(kali㉿kali)-[~]
└─$  curl -s http://inlanefreight.htb -H "Host: dmz.inlanefreight.htb"
<!doctype html>
<head>FLAG</head>
<body>
        HTB{7zbnr4i3n7zhrxn347zhh3dnrz4dh7zdjfbgn6d}
</body>
```
