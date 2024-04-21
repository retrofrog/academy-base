# Additional AD Auditing Techniques

Along with discussing the hardening of an AD domain, we wanted to discuss `AD auditing`. We want to provide our customers with as much information as possible to help solve the potential issues we find. Doing so will give them more data to prove they have a problem and help acquire backing and funding to tackle those fixes. The tools in this section can be utilized to provide different visualizations and data output for this purpose.

***

### Creating an AD Snapshot with Active Directory Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) is part of the Sysinternal Suite and is described as:

"An advanced Active Directory (AD) viewer and editor. You can use AD Explorer to navigate an AD database easily, define favorite locations, view object properties, and attributes without opening dialog boxes, edit permissions, view an object's schema, and execute sophisticated searches that you can save and re-execute."

AD Explorer can also be used to save snapshots of an AD database for offline viewing and comparison. We can take a snapshot of AD at a point in time and explore it later, during the reporting phase, as you would explore any other database. It can also be used to perform a before and after comparison of AD to uncover changes in objects, attributes, and security permissions.

When we first load the tool, we are prompted for login credentials or to load a previous snapshot. We can log in with any valid domain user.

**Logging in with AD Explorer**

![image](https://academy.hackthebox.com/storage/modules/47/AD\_explorer1.png)

Once logged in, we can freely browse AD and view information about all objects.

**Browsing AD with AD Explorer**

![image](https://academy.hackthebox.com/storage/modules/47/AD\_explorer\_logged\_in.png)

To take a snapshot of AD, go to File --> `Create Snapshot` and enter a name for the snapshot. Once it is complete, we can move it offline for further analysis.

**Creating a Snapshot of AD with AD Explorer**

![image](https://academy.hackthebox.com/storage/modules/47/AD\_explorer\_snapshot.png)

***

### PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) is a powerful tool that evaluates the security posture of an AD environment and provides us the results in several different maps and graphs. Thinking about security for a second, if you do not have an active inventory of the hosts in your enterprise, PingCastle can be a great resource to help you gather one in a nice user-readable map of the domain. PingCastle is different from tools such as PowerView and BloodHound because, aside from providing us with enumeration data that can inform our attacks, it also provides a detailed report of the target domain's security level using a methodology based on a risk assessment/maturity framework. The scoring shown in the report is based on the [Capability Maturity Model Integration](https://en.wikipedia.org/wiki/Capability\_Maturity\_Model\_Integration) (CMMI). For a quick look at the help context provided, you can issue the `--help` switch in cmd-prompt.

Note: If you are having issues with starting the tool, please change the date of the system to a date before 31st of July 2023 using the Control Panel (Set the time and date).

**Viewing the PingCastle Help Menu**

Additional AD Auditing Techniques

```cmd-session
C:\htb> PingCastle.exe --help

switch:
  --help              : display this message
  --interactive       : force the interactive mode
  --log               : generate a log file
  --log-console       : add log to the console
  --log-samba <option>: enable samba login (example: 10)

Common options when connecting to the AD
  --server <server>   : use this server (default: current domain controller)
                        the special value * or *.forest do the healthcheck for all domains
  --port <port>       : the port to use for ADWS or LDAP (default: 9389 or 389)
  --user <user>       : use this user (default: integrated authentication)
  --password <pass>   : use this password (default: asked on a secure prompt)
  --protocol <proto>  : selection the protocol to use among LDAP or ADWS (fastest)
                      : ADWSThenLDAP (default), ADWSOnly, LDAPOnly, LDAPThenADWS

<SNIP>  
```

**Running PingCastle**

To run PingCastle, we can call the executable by typing `PingCastle.exe` into our CMD or PowerShell window or by clicking on the executable, and it will drop us into interactive mode, presenting us with a menu of options inside the `Terminal User Interface` (`TUI`).

**PingCastle Interactive TUI**

Additional AD Auditing Techniques

```cmd-session
|:.      PingCastle (Version 2.10.1.0     1/19/2022 8:12:02 AM)
|  #:.   Get Active Directory Security at 80% in 20% of the time
# @@  >  End of support: 7/31/2023
| @@@:
: .#                                 Vincent LE TOUX (contact@pingcastle.com)
  .:       twitter: @mysmartlogon                    https://www.pingcastle.com
What do you want to do?
=======================
Using interactive mode.
Do not forget that there are other command line switches like --help that you can use
  1-healthcheck-Score the risk of a domain
  2-conso      -Aggregate multiple reports into a single one
  3-carto      -Build a map of all interconnected domains
  4-scanner    -Perform specific security checks on workstations
  5-export     -Export users or computers
  6-advanced   -Open the advanced menu
  0-Exit
==============================
This is the main functionnality of PingCastle. In a matter of minutes, it produces a report which will give you an overview of your Active Directory security. This report can be generated on other domains by using the existing trust links.
```

The default option is the `healthcheck` run, which will establish a baseline overview of the domain, and provide us with pertinent information dealing with misconfigurations and vulnerabilities. Even better, PingCastle can report recent vulnerability susceptibility, our shares, trusts, the delegation of permissions, and much more about our user and computer states. Under the Scanner option, we can find most of these checks.

**Scanner Options**

Additional AD Auditing Techniques

```cmd-session
|:.      PingCastle (Version 2.10.1.0     1/19/2022 8:12:02 AM)
|  #:.   Get Active Directory Security at 80% in 20% of the time
# @@  >  End of support: 7/31/2023
| @@@:
: .#                                 Vincent LE TOUX (contact@pingcastle.com)
  .:       twitter: @mysmartlogon                    https://www.pingcastle.com
Select a scanner
================
What scanner whould you like to run ?
WARNING: Checking a lot of workstations may raise security alerts.
  1-aclcheck                                                  9-oxidbindings
  2-antivirus                                                 a-remote
  3-computerversion                                           b-share
  4-foreignusers                                              c-smb
  5-laps_bitlocker                                            d-smb3querynetwork
  6-localadmin                                                e-spooler
  7-nullsession                                               f-startup
  8-nullsession-trust                                         g-zerologon
  0-Exit
==============================
Check authorization related to users or groups. Default to everyone, authenticated users and domain users
```

Now that we understand how it works and how to start scans, let's view the report.

**Viewing The Report**

Throughout the report, there are sections such as domain, user, group, and trust information and a specific table calling out "anomalies" or issues that may require immediate attention. We will also be presented with the domain's overall risk score.

![text](https://academy.hackthebox.com/storage/modules/143/report-example.png)

Aside from being helpful in performing very thorough domain enumeration when combined with other tools, PingCastle can be helpful to give clients a quick analysis of their domain security posture, or can be used by internal teams to self-assess and find areas of concern or opportunities for further hardening. Take some time to explore the reports and maps PingCastle can generate on the Inlanefreight domain.

**Group Policy**

With group policy being a large portion of how AD user and computer management is done, it's only logical that we would want to audit their settings and highlight any potential holes. `Group3r` is an excellent tool for this.

***

### Group3r

[Group3r](https://github.com/Group3r/Group3r) is a tool purpose-built to find vulnerabilities in Active Directory associated Group Policy. Group3r must be run from a domain-joined host with a domain user (it does not need to be an administrator), or in the context of a domain user (i.e., using `runas /netonly`).

**Group3r Basic Usage**

Additional AD Auditing Techniques

```cmd-session
C:\htb> group3r.exe -f <filepath-name.log> 
```

When running Group3r, we must specify the `-s` or the `-f` flag. These will specify whether to send results to stdout (-s), or to the file we want to send the results to (-f). For more options and usage information, utilize the `-h` flag, or check out the usage info at the link above.

Below is an example of starting Group3r.

**Reading Output**

![text](https://academy.hackthebox.com/storage/modules/143/grouper-output.png)

When reading the output from Group3r, each indentation is a different level, so no indent will be the GPO, one indent will be policy settings, and another will be findings in those settings. Below we will take a look at the output shown from a finding.

**Group3r Finding**

![text](https://academy.hackthebox.com/storage/modules/143/grouper-finding.png)

In the image above, you will see an example of a finding from Group3r. It will present it as a linked box to the policy setting, define the interesting portion and give us a reason for the finding. It is worth the effort to run Group3r if you have the opportunity. It will often find interesting paths or objects that other tools will overlook.

***

### ADRecon

Finally, there are several other tools out there that are useful for gathering a large amount of data from AD at once. In an assessment where stealth is not required, it is also worth running a tool like [ADRecon](https://github.com/adrecon/ADRecon) and analyzing the results, just in case all of our enumeration missed something minor that may be useful to us or worth pointing out to our client.

**Running ADRecon**

Additional AD Auditing Techniques

```powershell-session
PS C:\htb> .\ADRecon.ps1

[*] ADRecon v1.1 by Prashant Mahajan (@prashant3535)
[*] Running on INLANEFREIGHT.LOCAL\MS01 - Member Server
[*] Commencing - 03/28/2022 09:24:58
[-] Domain
[-] Forest
[-] Trusts
[-] Sites
[-] Subnets
[-] SchemaHistory - May take some time
[-] Default Password Policy
[-] Fine Grained Password Policy - May need a Privileged Account
[-] Domain Controllers
[-] Users and SPNs - May take some time
[-] PasswordAttributes - Experimental
[-] Groups and Membership Changes - May take some time
[-] Group Memberships - May take some time
[-] OrganizationalUnits (OUs)
[-] GPOs
[-] gPLinks - Scope of Management (SOM)
[-] DNS Zones and Records
[-] Printers
[-] Computers and SPNs - May take some time
[-] LAPS - Needs Privileged Account
[-] BitLocker Recovery Keys - Needs Privileged Account
[-] GPOReport - May take some time
[*] Total Execution Time (mins): 11.05
[*] Output Directory: C:\Tools\ADRecon-Report-20220328092458
```

Once done, ADRecon will drop a report for us in a new folder under the directory we executed from. We can see an example of the results in the terminal below. You will get a report in HTML format and a folder with CSV results. When generating the report, it should be noted that the program Excel needs to be installed, or the script will not automatically generate the report in that manner; it will just leave you with the .csv files. If you want output for Group Policy, you need to ensure the host you run from has the `GroupPolicy` PowerShell module installed. We can go back later and generate the Excel report from another host using the `-GenExcel` switch and feeding in the report folder.

**Reporting**

Additional AD Auditing Techniques

```powershell-session
PS C:\htb> ls

    Directory: C:\Tools\ADRecon-Report-20220328092458

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         3/28/2022  12:42 PM                CSV-Files
-a----         3/28/2022  12:42 PM        2758736 GPO-Report.html
-a----         3/28/2022  12:42 PM         392780 GPO-Report.xml
```

***

We have covered so many tools and tactics within this module, but we felt it was prudent to show and explain a few other ways to audit a target domain. Keep in mind that your actions should serve a purpose, and our end goal is to make the customer's security posture better. So with that in mind, acquiring more evidence of issues will only serve to:

`Make our reporting more convincing and provide the customer with the tools they need to fix & actively secure their domain`.
