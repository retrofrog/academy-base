# Information Gathering - Web - Skills Assessment

You've just decided to join in on the GitHub [bug bounty](https://bounty.github.com/) program after a friend of yours got a large payout for a critical RCE flaw. After reading the rules carefully, you begin with passive and active information gathering and enumeration to attempt to uncover an interesting target. After reviewing the [scope](https://bounty.github.com/#scope), you decide to target the `githubapp.com` domain.

The description of this domain reads as follows:

## Information Gathering - Web - Skills Assessment

```shell-session

githubapp.com

This is our domain for hosting employee-facing services. 

All subdomains under githubapp.com are in-scope except:

- atom-io.githubapp.com
- atom-io-staging.githubapp.com
- email.enterprise-staging.githubapp.com
- email.haystack.githubapp.com
- reply.githubapp.com
```

Perform passive and active information gathering against this domain and answer the questions below to complete the skills assessment and finish this module.

## Walkthrough

### What is the registrar IANA ID number for the githubapp.com domain?

```bash
whois githubapp.com
   Registrar IANA ID: 292
```

### What is the last mailserver returned when querying the MX records for githubapp.com?

```bash
dig mx githubapp.com
;; ANSWER SECTION:
githubapp.com.          5       IN      MX      10 aspmx.l.google.com.
githubapp.com.          5       IN      MX      20 alt1.aspmx.l.google.com.
githubapp.com.          5       IN      MX      20 alt2.aspmx.l.google.com.
githubapp.com.          5       IN      MX      30 aspmx2.googlemail.com.
githubapp.com.          5       IN      MX      30 aspmx3.googlemail.com.
githubapp.com.          5       IN      MX      30 aspmx4.googlemail.com.
githubapp.com.          5       IN      MX      30 aspmx5.googlemail.com.
```

### Perform active infrastructure identification against the host https://i.imgur.com. What server name is returned for the host?

```
┌──(kali㉿kali)-[~]
└─$ curl -I https://i.imgur.com                                  
HTTP/2 302 
retry-after: 0
location: https://imgur.com/
accept-ranges: bytes
date: Thu, 15 Feb 2024 16:24:28 GMT
x-served-by: cache-lax-kwhp1940045-LAX
x-cache: HIT
x-cache-hits: 0
x-timer: S1708014268.394525,VS0,VE0
strict-transport-security: max-age=300
access-control-allow-methods: GET, OPTIONS
access-control-allow-origin: *
server: cat factory 1.0
content-length: 0
```

cat factory 1.0

### Perform subdomain enumeration against the target githubapp.com. Which subdomain has the word 'triage' in the name?

```bash
#https://crt.sh/?q=githubapp.com
data-triage-reports.githubapp.com
```
