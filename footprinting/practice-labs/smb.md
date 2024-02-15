# SMB

### What version of the SMB server is running on the target system? Submit the entire banner as the answer.

```bash
nmap -sV --script=banner 10.129.113.69 -p445
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-14 08:58 EST
Nmap scan report for 10.129.113.69 (10.129.113.69)
Host is up (0.27s latency).

PORT    STATE SERVICE     VERSION
445/tcp open  netbios-ssn Samba smbd 4.6.2
```

Samba smbd 4.6.2

### What is the name of the accessible share on the target?

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ smbmap -H 10.129.113.69                                                      
[+] IP: 10.129.113.69:445       Name: 10.129.113.69             Status: Authenticated
        Disk                            Permissions     Comment
        ----                            -----------     -------
        print$                          NO ACCESS       Printer Drivers
        sambashare                      READ ONLY       InFreight SMB v3.1
        IPC$                            NO ACCESS       IPC Service (InlaneFreight SMB server (Samba, Ubuntu))
```

sambashare

### Connect to the discovered share and find the flag.txt file. Submit the contents as the answer.

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ smbclient //10.129.113.69/sambashare
Password for [WORKGROUP\kali]:anonymous
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Nov  8 08:43:14 2021
  ..                                  D        0  Mon Nov  8 10:53:19 2021
  .profile                            H      807  Tue Feb 25 07:03:22 2020
  contents                            D        0  Mon Nov  8 08:43:45 2021
  .bash_logout                        H      220  Tue Feb 25 07:03:22 2020
  .bashrc                             H     3771  Tue Feb 25 07:03:22 2020

                4062912 blocks of size 1024. 414236 blocks available
smb: \> cd contents
smb: \contents\> ls
  .                                   D        0  Mon Nov  8 08:43:45 2021
  ..                                  D        0  Mon Nov  8 08:43:14 2021
  flag.txt                            N       38  Mon Nov  8 08:43:45 2021

                4062912 blocks of size 1024. 414236 blocks available
smb: \contents\> get flag.txt
getting file \contents\flag.txt of size 38 as flag.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \contents\> exit
                                                                                                                                                              
┌──(kali㉿kali)-[~/Desktop]
└─$ cat flag.txt 
HTB{o873nz4xdo873n4zo873zn4fksuhldsf}
```

### Find out which domain the server belongs to.

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ rpcclient -U '' 10.129.113.69
Password for [WORKGROUP\]:anonymous
rpcclient $> querydominfo
Domain:         DEVOPS
Server:         DEVSMB
Comment:        InlaneFreight SMB server (Samba, Ubuntu)
Total Users:    0
Total Groups:   0
Total Aliases:  0
Sequence No:    1707920216
Force Logoff:   -1
Domain Server State:    0x1
Server Role:    ROLE_DOMAIN_PDC
Unknown 3:      0x1
```

DEVOPS

### Find additional information about the specific share we found previously and submit the customized version of that specific share as the answer.

```bash
rpcclient $> netshareenumall
netname: print$
        remark: Printer Drivers
        path:   C:\var\lib\samba\printers
        password:
netname: sambashare
        remark: InFreight SMB v3.1
        path:   C:\home\sambauser\
        password:
netname: IPC$
        remark: IPC Service (InlaneFreight SMB server (Samba, Ubuntu))
        path:   C:\tmp
        password:
```

InFreight SMB v3.1

### What is the full system path of that specific share?

/home/sambauser
