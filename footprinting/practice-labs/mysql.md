# MySQL

### Enumerate the MySQL server and determine the version in use. (Format: MySQL X.X.XX)

```bash
sudo nmap 10.129.42.195 -sV -sC -p3306 --script mysql* -T4 -oN nmap.txt
PORT     STATE SERVICE VERSION
3306/tcp open  mysql   MySQL 8.0.27-0ubuntu0.20.04.1
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.27-0ubuntu0.20.04.1
|   Thread ID: 229
|   Capabilities flags: 65535
|   Some Capabilities: Support41Auth, DontAllowDatabaseTableColumn, SupportsTransactions, Speaks41ProtocolOld, IgnoreSpaceBeforeParenthesis, SupportsLoadDataLocal, LongPassword, SupportsCompression, FoundRows, IgnoreSigpipes, LongColumnFlag, ODBCClient, InteractiveClient, SwitchToSSLAfterHandshake, Speaks41ProtocolNew, ConnectWithDatabase, SupportsAuthPlugins, SupportsMultipleResults, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: kM\x13        sn\x17gbj'\x14}BJa\x14V%m
|_  Auth Plugin Name: caching_sha2_password
| mysql-enum: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 9 guesses in 6 seconds, average tps: 1.5
| mysql-brute: 
|   Accounts: No valid accounts found
|   Statistics: Performed 8684 guesses in 302 seconds, average tps: 29.4
|_  ERROR: The service seems to have failed or is heavily firewalled...
```

```
MySQL 8.0.27
```

### During our penetration test, we found weak credentials "robin:robin". We should try these against the MySQL server. What is the email address of the customer "Otto Lang

```bash
mysql -u robin -probin -h 10.129.42.195
```

```sql
show databases;
select version();
use customers;
select * from myTable;
select * from myTable where name = "Otto Lang";                                          
```

ultrices@google.htb
