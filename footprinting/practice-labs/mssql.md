# MSSQL

### Enumerate the target using the concepts taught in this section. List the hostname of MSSQL server.

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.241.176
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-15 03:32 EST
Nmap scan report for 10.129.241.176 (10.129.241.176)
Host is up (0.24s latency).

Bug in ms-sql-hasdbaccess: no string output.
Bug in ms-sql-dac: no string output.
PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   10.129.241.176:1433: 
|     Target_Name: ILF-SQL-01
|     NetBIOS_Domain_Name: ILF-SQL-01
|     NetBIOS_Computer_Name: ILF-SQL-01
|     DNS_Domain_Name: ILF-SQL-01
|     DNS_Computer_Name: ILF-SQL-01
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.129.241.176:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-config: 
|   10.129.241.176:1433: 
|_  ERROR: Bad username or password
| ms-sql-xp-cmdshell: 
|_  (Use --script-args=ms-sql-xp-cmdshell.cmd='<CMD>' to change command.)
| ms-sql-empty-password: 
|_  10.129.241.176:1433: 
| ms-sql-tables: 
|   10.129.241.176:1433: 
|_[10.129.241.176:1433]
| ms-sql-dump-hashes: 
|_  10.129.241.176:1433: ERROR: Bad username or password
```

ILF-SQL-01

### Connect to the MSSQL instance running on the target using the account (backdoor:Password1), then list the non-default database present on the server.

```bash
impacket-mssqlclient backdoor@10.129.241.176 -windows-auth
SQL (ILF-SQL-01\backdoor  dbo@master)> select name from sys.databases
name        
---------   
master      

tempdb      

model       

msdb        

Employees 
```

Employees
