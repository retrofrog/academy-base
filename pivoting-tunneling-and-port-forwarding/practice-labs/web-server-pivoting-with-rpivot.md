# Web Server Pivoting with Rpivot

Using the concepts taught in this section, connect to the web server on the internal network. Submit the flag presented on the home page as the answer.

```bash
sudo git clone https://github.com/klsecservices/rpivot.git
python2 server.py
scp -r rpivot ubuntu@10.129.7.236:/home/ubuntu/
```

from the target

```bash
python2.7 client.py --server-ip 10.10.14.18 --server-port 9050
```

Browsing to the Target Webserver using Proxychains

```bash
proxychains firefox-esr 172.16.5.135:80
```
