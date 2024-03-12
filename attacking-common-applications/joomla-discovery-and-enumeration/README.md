# Joomla - Discovery & Enumeration

[Joomla](https://www.joomla.org/), released in August 2005 is another free and open-source CMS used for discussion forums, photo galleries, e-Commerce, user-based communities, and more. It is written in PHP and uses MySQL in the backend. Like WordPress, Joomla can be enhanced with over 7,000 extensions and over 1,000 templates. There are up to 2.5 million sites on the internet running Joomla. Here are some interesting [statistics](https://websitebuilder.org/blog/joomla-statistics/) about Joomla:

* Joomla accounts for 3.5% of the CMS market share
* Joomla is 100% free and means "all together" in Swahili (phonetic spelling of "Jumla")
* The Joomla community has close to 700,000 in its online forums
* Joomla powers 3% of all websites on the internet, nearly 25,000 of the top 1 million sites worldwide (just 10% of the reach of WordPress)
* Some notable organizations that use Joomla include eBay, Yamaha, Harvard University, and the UK government
* Over the years, 770 different developers have contributed to Joomla

Joomla collects some anonymous [usage statistics](https://developer.joomla.org/about/stats.html) such as the breakdown of Joomla, PHP and database versions and server operating systems in use on Joomla installations. This data can be queried via their public [API](https://developer.joomla.org/about/stats/api.html).

Querying this API, we can see over 2.7 million Joomla installs!

Joomla - Discovery & Enumeration

```shell-session
AIceBear@htb[/htb]$ curl -s https://developer.joomla.org/stats/cms_version | python3 -m json.tool

{
    "data": {
        "cms_version": {
            "3.0": 0,
            "3.1": 0,
            "3.10": 3.49,
            "3.2": 0.01,
            "3.3": 0.02,
            "3.4": 0.05,
            "3.5": 13,
            "3.6": 24.29,
            "3.7": 8.5,
            "3.8": 18.84,
            "3.9": 30.28,
            "4.0": 1.52,
            "4.1": 0
        },
        "total": 2776276
    }
}
```

***

### Discovery/Footprinting

Let's assume that we come across an e-commerce site during an external penetration test. At first glance, we are not exactly sure what is running, but it does not appear to be fully custom. If we can fingerprint what the site is running on, we may be able to uncover vulnerabilities or misconfigurations. Based on the limited information, we assume that the site is running Joomla, but we must confirm that fact and then figure out the version number and other information such as installed themes and plugins.

We can often fingerprint Joomla by looking at the page source, which tells us that we are dealing with a Joomla site.

Joomla - Discovery & Enumeration

```shell-session
AIceBear@htb[/htb]$ curl -s http://dev.inlanefreight.local/ | grep Joomla

	<meta name="generator" content="Joomla! - Open Source Content Management" />


<SNIP>
```

The `robots.txt` file for a Joomla site will often look like this:

Joomla - Discovery & Enumeration

```shell-session
# If the Joomla site is installed within a folder
# eg www.example.com/joomla/ then the robots.txt file
# MUST be moved to the site root
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths.
# eg the Disallow rule for the /administrator/ folder MUST
# be changed to read
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# https://www.robotstxt.org/orig.html

User-agent: *
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

We can also often see the telltale Joomla favicon (but not always). We can fingerprint the Joomla version if the `README.txt` file is present.

Joomla - Discovery & Enumeration

```shell-session
AIceBear@htb[/htb]$ curl -s http://dev.inlanefreight.local/README.txt | head -n 5

1- What is this?
	* This is a Joomla! installation/upgrade package to version 3.x
	* Joomla! Official site: https://www.joomla.org
	* Joomla! 3.9 version history - https://docs.joomla.org/Special:MyLanguage/Joomla_3.9_version_history
	* Detailed changes in the Changelog: https://github.com/joomla/joomla-cms/commits/staging
```

In certain Joomla installs, we may be able to fingerprint the version from JavaScript files in the `media/system/js/` directory or by browsing to `administrator/manifests/files/joomla.xml`.

Joomla - Discovery & Enumeration

```shell-session
AIceBear@htb[/htb]$ curl -s http://dev.inlanefreight.local/administrator/manifests/files/joomla.xml | xmllint --format -

<?xml version="1.0" encoding="UTF-8"?>
<extension version="3.6" type="file" method="upgrade">
  <name>files_joomla</name>
  <author>Joomla! Project</author>
  <authorEmail>admin@joomla.org</authorEmail>
  <authorUrl>www.joomla.org</authorUrl>
  <copyright>(C) 2005 - 2019 Open Source Matters. All rights reserved</copyright>
  <license>GNU General Public License version 2 or later; see LICENSE.txt</license>
  <version>3.9.4</version>
  <creationDate>March 2019</creationDate>
  
 <SNIP>
```

The `cache.xml` file can help to give us the approximate version. It is located at `plugins/system/cache/cache.xml`.

***

### Enumeration

Let's try out [droopescan](https://github.com/droope/droopescan), a plugin-based scanner that works for SilverStripe, WordPress, and Drupal with limited functionality for Joomla and Moodle.

We can clone the Git repo and install it manually or install via `pip`.

Joomla - Discovery & Enumeration

```shell-session
AIceBear@htb[/htb]$ sudo pip3 install droopescan

Collecting droopescan
  Downloading droopescan-1.45.1-py2.py3-none-any.whl (514 kB)
     |████████████████████████████████| 514 kB 5.8 MB/s
	 
<SNIP>
```

Once the installation is complete, we can confirm that the tool is working by running `droopescan -h`.

Joomla - Discovery & Enumeration

```shell-session
AIceBear@htb[/htb]$ droopescan -h

usage: droopescan (sub-commands ...) [options ...] {arguments ...}

    |
 ___| ___  ___  ___  ___  ___  ___  ___  ___  ___
|   )|   )|   )|   )|   )|___)|___ |    |   )|   )
|__/ |    |__/ |__/ |__/ |__   __/ |__  |__/||  /
                    |
=================================================

commands:

  scan
    cms scanning functionality.

  stats
    shows scanner status & capabilities.

optional arguments:
  -h, --help  show this help message and exit
  --debug     toggle debug output
  --quiet     suppress all output

Example invocations: 
  droopescan scan drupal -u URL_HERE
  droopescan scan silverstripe -u URL_HERE

More info: 
  droopescan scan --help
 
Please see the README file for information regarding proxies.
```

We can access a more detailed help menu by typing `droopescan scan --help`.

Let's run a scan and see what it turns up.

Joomla - Discovery & Enumeration

```shell-session
AIceBear@htb[/htb]$ droopescan scan joomla --url http://dev.inlanefreight.local/

[+] Possible version(s):                                                        
    3.8.10
    3.8.11
    3.8.11-rc
    3.8.12
    3.8.12-rc
    3.8.13
    3.8.7
    3.8.7-rc
    3.8.8
    3.8.8-rc
    3.8.9
    3.8.9-rc

[+] Possible interesting urls found:
    Detailed version information. - http://dev.inlanefreight.local/administrator/manifests/files/joomla.xml
    Login page. - http://dev.inlanefreight.local/administrator/
    License file. - http://dev.inlanefreight.local/LICENSE.txt
    Version attribute contains approx version - http://dev.inlanefreight.local/plugins/system/cache/cache.xml

[+] Scan finished (0:00:01.523369 elapsed)
```

As we can see, it did not turn up much information aside from the possible version number. We can also try out [JoomlaScan](https://github.com/drego85/JoomlaScan), which is a Python tool inspired by the now-defunct OWASP [joomscan](https://github.com/OWASP/joomscan) tool. `JoomlaScan` is a bit out-of-date and requires Python2.7 to run. We can get it running by first making sure some dependencies are installed.

Joomla - Discovery & Enumeration

```shell-session
AIceBear@htb[/htb]$ sudo python2.7 -m pip install urllib3
AIceBear@htb[/htb]$ sudo python2.7 -m pip install certifi
AIceBear@htb[/htb]$ sudo python2.7 -m pip install bs4
```

While a bit out of date, it can be helpful in our enumeration. Let's run a scan.

Joomla - Discovery & Enumeration

```shell-session
AIceBear@htb[/htb]$ python2.7 joomlascan.py -u http://dev.inlanefreight.local

-------------------------------------------
      	     Joomla Scan                  
   Usage: python joomlascan.py <target>    
    Version 0.5beta - Database Entries 1233
         created by Andrea Draghetti       
-------------------------------------------
Robots file found: 	 	 > http://dev.inlanefreight.local/robots.txt
No Error Log found

Start scan...with 10 concurrent threads!
Component found: com_actionlogs	 > http://dev.inlanefreight.local/index.php?option=com_actionlogs
	 On the administrator components
Component found: com_admin	 > http://dev.inlanefreight.local/index.php?option=com_admin
	 On the administrator components
Component found: com_ajax	 > http://dev.inlanefreight.local/index.php?option=com_ajax
	 But possibly it is not active or protected
	 LICENSE file found 	 > http://dev.inlanefreight.local/administrator/components/com_actionlogs/actionlogs.xml
	 LICENSE file found 	 > http://dev.inlanefreight.local/administrator/components/com_admin/admin.xml
	 LICENSE file found 	 > http://dev.inlanefreight.local/administrator/components/com_ajax/ajax.xml
	 Explorable Directory 	 > http://dev.inlanefreight.local/components/com_actionlogs/
	 Explorable Directory 	 > http://dev.inlanefreight.local/administrator/components/com_actionlogs/
	 Explorable Directory 	 > http://dev.inlanefreight.local/components/com_admin/
	 Explorable Directory 	 > http://dev.inlanefreight.local/administrator/components/com_admin/
Component found: com_banners	 > http://dev.inlanefreight.local/index.php?option=com_banners
	 But possibly it is not active or protected
	 Explorable Directory 	 > http://dev.inlanefreight.local/components/com_ajax/
	 Explorable Directory 	 > http://dev.inlanefreight.local/administrator/components/com_ajax/
	 LICENSE file found 	 > http://dev.inlanefreight.local/administrator/components/com_banners/banners.xml


<SNIP>
```

While not as valuable as droopescan, this tool can help us find accessible directories and files and may help with fingerprinting installed extensions. At this point, we know that we are dealing with Joomla `3.9.4`. The administrator login portal is located at `http://dev.inlanefreight.local/administrator/index.php`. Attempts at user enumeration return a generic error message.

Joomla - Discovery & Enumeration

```shell-session
Warning
Username and password do not match or you do not have an account yet.
```

The default administrator account on Joomla installs is `admin`, but the password is set at install time, so the only way we can hope to get into the admin back-end is if the account is set with a very weak/common password and we can get in with some guesswork or light brute-forcing. We can use this [script](https://github.com/ajnik/joomla-bruteforce) to attempt to brute force the login.

Joomla - Discovery & Enumeration

```shell-session
AIceBear@htb[/htb]$ sudo python3 joomla-brute.py -u http://dev.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
 
admin:admin
```

And we get a hit with the credentials `admin:admin`. Someone has not been following best practices!

**Questions**

Fingerprint the Joomla version in use on http://app.inlanefreight.local (Format: x.x.x)

```bash
#1
curl -s http://app.inlanefreight.local/administrator/manifests/files/joomla.xml | xmllint --format -
  <version>3.10.0</version>
#2
droopescan scan joomla --url http://app.inlanefreight.local/
[+] Possible version(s):                                                        
    3.10.0-alpha1
```

Find the password for the admin user on http://app.inlanefreight.local

```bash
git clone https://github.com/ajnik/joomla-bruteforce
cd joomla-bruteforce
sudo python3 joomla-brute.py -u http://app.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
admin:turnkey
```
