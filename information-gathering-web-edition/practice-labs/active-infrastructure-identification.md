# Active Infrastructure Identification

vHosts needed for these questions:

* `app.inlanefreight.local`
* `dev.inlanefreight.local`

### What Apache version is running on app.inlanefreight.local? (Format: 0.0.0)

```bash
┌──(kali㉿kali)-[~]
└─$ curl -I "http://app.inlanefreight.local"
HTTP/1.1 200 OK
Date: Thu, 15 Feb 2024 15:26:02 GMT
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: 72af8f2b24261272e581a49f5c56de40=v3scf5soluq7pdejhc7vf78b1v; path=/; HttpOnly
Permissions-Policy: interest-cohort=()
Expires: Wed, 17 Aug 2005 00:00:00 GMT
Last-Modified: Thu, 15 Feb 2024 15:26:13 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Content-Type: text/html; charset=utf-8
```

2.4.41

### Which CMS is used on app.inlanefreight.local? (Format: word)

```bash
┌──(kali㉿kali)-[~]
└─$ whatweb -a3 http://app.inlanefreight.local -v
[ MetaGenerator ]
        This plugin identifies meta generator tags and extracts its 
        value. 
        String       : Joomla! - Open Source Content Management
```

Joomla

### On which operating system is the dev.inlanefreight.local webserver running on? (Format: word)

```bash
┌──(kali㉿kali)-[~]
└─$ curl -I "http://dev.inlanefreight.local"  
HTTP/1.1 200 OK
Date: Thu, 15 Feb 2024 15:30:29 GMT
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: 02a93f6429c54209e06c64b77be2180d=govlhp9anjrbfnkf3hiq7ss9vd; path=/; HttpOnly
Expires: Wed, 17 Aug 2005 00:00:00 GMT
Last-Modified: Thu, 15 Feb 2024 15:30:38 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Content-Type: text/html; charset=utf-8
```

ubuntu
