# Determine Login Parameters

We can easily find POST parameters if we intercept the login request with Burp Suite or take a closer look at the admin panel's source code.

***

### Using Browser

One of the easiest ways to capture a form's parameters is through using a browser's built in developer tools. For example, we can open firefox within PwnBox, and then bring up the Network Tools with `[CTRL + SHIFT + E]`.

Once we do, we can simply try to login with any credentials (`test`:`test`) to run the form, after which the Network Tools would show the sent HTTP requests. Once we have the request, we can simply right-click on one of them, and select `Copy` > `Copy POST data`:

![FoxyProxy](https://academy.hackthebox.com/storage/modules/57/bruteforcing\_firefox\_network\_1.jpg)

This would give us the following POST parameters:

Code: bash

```bash
username=test&password=test
```

Another option would be to used `Copy` > `Copy as cURL`, which would copy the entire `cURL` command, which we can use in the Terminal to repeat the same HTTP request:

Determine Login Parameters

```shell-session
AIceBear@htb[/htb]$ curl 'http://178.128.40.63:31554/login.php' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: http://178.128.40.63:31554' -H 'DNT: 1' -H 'Connection: keep-alive' -H 'Referer: http://178.128.40.63:31554/login.php' -H 'Cookie: PHPSESSID=8iafr4t6c3s2nhkaj63df43v05' -H 'Upgrade-Insecure-Requests: 1' -H 'Sec-GPC: 1' --data-raw 'username=test&password=test'
```

As we can see, this command also contains the parameters `--data-raw 'username=test&password=test'`.

***

### Using Burp Suite

In case we were dealing with a web page that sends many HTTP requests, it may be easier to use Burp Suite in order to go through all sent HTTP requests, and pick the ones we are interested in. To do that, we will first start BurpSuite from Application Dock at the bottom in Pwnbox, skip all the messages until the application starts, and then Click on the `Proxy` tab:

![FoxyProxy](https://academy.hackthebox.com/storage/modules/57/web\_fnb\_burp.jpg)

Next, We will go to Firefox and enable the `Burp Proxy` by clicking on the `FoxyProxy` button in Firefox, and then choosing `Burp`, as seen in the screenshot below:

![FoxyProxy](https://academy.hackthebox.com/storage/modules/57/bruteforcing\_foxyproxy\_1.jpg)

Now, all we will do is attempt a login with any username/password 'e.g. `admin:admin`', and go back to BurpSuite, to find the login request captured: ![FoxyProxy](https://academy.hackthebox.com/storage/modules/57/bruteforcing\_burp\_request\_1.jpg)

Tip: If we find another request captured, we can click "Forward" until we reach our request from "/login.php".

What we need from the above-captured string is the very last line:

Code: bash

```bash
username=admin&password=admin
```

To use in a `hydra http-post-form`, we can take it as is, and replace the username/password we used `admin:admin` with `^USER^` and `^PASS^`. The specification of our final target path should be as follows:

Code: bash

```bash
"/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
```
