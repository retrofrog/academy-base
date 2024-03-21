# Session Fixation

Session Fixation occurs when an attacker can fixate a (valid) session identifier. As you can imagine, the attacker will then have to trick the victim into logging into the application using the aforementioned session identifier. If the victim does so, the attacker can proceed to a Session Hijacking attack (since the session identifier is already known).

Such bugs usually occur when session identifiers (such as cookies) are being accepted from _URL Query Strings_ or _Post Data_ (more on that in a bit).

Session Fixation attacks are usually mounted in three stages:

**Stage 1: Attacker manages to obtain a valid session identifier**

Authenticating to an application is not always a requirement to get a valid session identifier, and a large number of applications assign valid session identifiers to anyone who browses them. This also means that an attacker can be assigned a valid session identifier without having to authenticate.

**Note**: An attacker can also obtain a valid session identifier by creating an account on the targeted application (if this is a possibility).

**Stage 2: Attacker manages to fixate a valid session identifier**

The above is expected behavior, but it can turn into a session fixation vulnerability if:

* The assigned session identifier pre-login remains the same post-login `and`
* Session identifiers (such as cookies) are being accepted from _URL Query Strings_ or _Post Data_ and propagated to the application

If, for example, a session-related parameter is included in the URL (and not on the cookie header) and any specified value eventually becomes a session identifier, then the attacker can fixate a session.

**Stage 3: Attacker tricks the victim into establishing a session using the abovementioned session identifier**

All the attacker has to do is craft a URL and lure the victim into visiting it. If the victim does so, the web application will then assign this session identifier to the victim.

The attacker can then proceed to a session hijacking attack since the session identifier is already known.

***

### Session Fixation Example

Proceed to the end of this section and click on `Click here to spawn the target system!` or the `Reset Target` icon. Use the provided Pwnbox or a local VM with the supplied VPN key to reach the target application and follow along. Don't forget to configure the specified vhost (`oredirect.htb.net`) to access the application.

**Part 1: Session fixation identification**

Navigate to `oredirect.htb.net`. You will come across a URL of the below format:

`http://oredirect.htb.net/?redirect_uri=/complete.html&token=<RANDOM TOKEN VALUE>`

Using Web Developer Tools (Shift+Ctrl+I in the case of Firefox), notice that the application uses a session cookie named `PHPSESSID` and that the cookie's value is the same as the `token` parameter's value on the URL.

![image](https://academy.hackthebox.com/storage/modules/153/18.png)

If any value or a valid session identifier specified in the `token` parameter on the URL is propagated to the `PHPSESSID` cookie's value, we are probably dealing with a session fixation vulnerability.

Let us see if that is the case, as follows.

**Part 2: Session fixation exploitation attempt**

Open a `New Private Window` and navigate to `http://oredirect.htb.net/?redirect_uri=/complete.html&token=IControlThisCookie`

Using Web Developer Tools (Shift+Ctrl+I in the case of Firefox), notice that the `PHPSESSID` cookie's value is `IControlThisCookie`

![image](https://academy.hackthebox.com/storage/modules/153/19.png)

We are dealing with a Session Fixation vulnerability. An attacker could send a URL similar to the above to a victim. If the victim logs into the application, the attacker could easily hijack their session since the session identifier is already known (the attacker fixated it).

**Note**: Another way of identifying this is via blindly putting the session identifier name and value in the URL and then refreshing.

For example, suppose we are looking into `http://insecure.exampleapp.com/login` for session fixation bugs, and the session identifier being used is a cookie named `PHPSESSID`. To test for session fixation, we could try the following `http://insecure.exampleapp.com/login?PHPSESSID=AttackerSpecifiedCookieValue` and see if the specified cookie value is propagated to the application (as we did in this section's lab exercise).

Below is the vulnerable code of this section's lab exercise.

Code: php

```php
<?php
    if (!isset($_GET["token"])) {
        session_start();
        header("Location: /?redirect_uri=/complete.html&token=" . session_id());
    } else {
        setcookie("PHPSESSID", $_GET["token"]);
    }
?>
```

Let us break the above piece of code down.

Code: php

```php
if (!isset($_GET["token"])) {
     session_start();
```

The above piece of code can be translated as follows: If the _token_ parameter hasn't been defined, start a session (generate and provide a valid session identifier).

Code: php

```php
header("Location: /?redirect_uri=/complete.html&token=" . session_id());
```

The above piece of code can be translated as follows: Redirect the user to `/?redirect_uri=/complete.html&token=` and then call the _session\_id()_ function to append _session\_id_ onto the token value.

Code: php

```php
 } else {
        setcookie("PHPSESSID", $_GET["token"]);
    }
```

The above piece of code can be translated as follows: If the _token_ parameter is already set (else statement), set _PHPSESSID_ to the value of the _token_ parameter. Any URL in the following format `http://oredirect.htb.net/?redirect_uri=/complete.html&token=AttackerSpecifiedCookieValue` will update _PHPSESSID_'s value with the _token_ parameter's value.

By now, we have covered session hijacking and session fixation. Moving forward, let us see some ways through which a bug bounty hunter or penetration tester can obtain valid session identifiers that can be then used to hijack a user's session.

**Questions**

If the HttpOnly flag was set, would the application still be vulnerable to session fixation? Answer Format: Yes or No

```
Yes
```
