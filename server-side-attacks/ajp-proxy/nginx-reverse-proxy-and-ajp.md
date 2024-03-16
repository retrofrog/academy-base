# Nginx Reverse Proxy & AJP

When we come across an open AJP proxy port (8009 TCP), we can use Nginx with the `ajp_module` to access the "hidden" Tomcat Manager. This can be done by compiling the Nginx source code and adding the required module, as follows:

* Download the Nginx source code
* Download the required module
* Compile Nginx source code with the `ajp_module`.
* Create a configuration file pointing to the AJP Port

**Download Nginx Source Code**

Nginx Reverse Proxy & AJP

```shell-session
AIceBear@htb[/htb]$ wget https://nginx.org/download/nginx-1.21.3.tar.gz
AIceBear@htb[/htb]$ tar -xzvf nginx-1.21.3.tar.gz
```

**Compile Nginx source code with the ajp module**

Nginx Reverse Proxy & AJP

```shell-session
AIceBear@htb[/htb]$ git clone https://github.com/dvershinin/nginx_ajp_module.git
AIceBear@htb[/htb]$ cd nginx-1.21.3
AIceBear@htb[/htb]$ sudo apt install libpcre3-dev
AIceBear@htb[/htb]$ ./configure --add-module=`pwd`/../nginx_ajp_module --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib/nginx/modules
AIceBear@htb[/htb]$ make
AIceBear@htb[/htb]$ sudo make install
AIceBear@htb[/htb]$ nginx -V

nginx version: nginx/1.21.3
built by gcc 10.2.1 20210110 (Debian 10.2.1-6)
configure arguments: --add-module=../nginx_ajp_module --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib/nginx/modules
```

Note: In the following configuration, we are using port 8009, which is Tomcat's default port for AJP, and this is how we would use it in a real environment. However, to complete the exercise at the end of this section you should specify the IP and port of the target you will spawn (they will both be visible right next to "Target:"). The port you will see is essentially mapped to port 8009 of the underlying Docker container.

Comment out the entire `server` block and append the following lines inside the `http` block in `/etc/nginx/conf/nginx.conf`.

**Pointing to the AJP Port**

Nginx Reverse Proxy & AJP

```shell-session
upstream tomcats {
	server <TARGET_SERVER>:8009;
	keepalive 10;
	}
server {
	listen 80;
	location / {
		ajp_keep_conn on;
		ajp_pass tomcats;
	}
}
```

Note: If you are using Pwnbox, then port 80 will be in use already, so, in the above configuration change port 80 to 8080. Finally, in the next step, use port 8080 with cURL.

Start Nginx and check if everything is working correctly by issuing a cURL request to your local host.

Nginx Reverse Proxy & AJP

```shell-session
AIceBear@htb[/htb]$ sudo nginx
AIceBear@htb[/htb]$ curl http://127.0.0.1:80

<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8" />
        <title>Apache Tomcat/X.X.XX</title>
        <link href="favicon.ico" rel="icon" type="image/x-icon" />
        <link href="favicon.ico" rel="shortcut icon" type="image/x-icon" />
        <link href="tomcat.css" rel="stylesheet" type="text/css" />
    </head>

    <body>
        <div id="wrapper">
            <div id="navigation" class="curved container">
                <span id="nav-home"><a href="https://tomcat.apache.org/">Home</a></span>
                <span id="nav-hosts"><a href="/docs/">Documentation</a></span>
                <span id="nav-config"><a href="/docs/config/">Configuration</a></span>
                <span id="nav-examples"><a href="/examples/">Examples</a></span>
                <span id="nav-wiki"><a href="https://wiki.apache.org/tomcat/FrontPage">Wiki</a></span>
                <span id="nav-lists"><a href="https://tomcat.apache.org/lists.html">Mailing Lists</a></span>
                <span id="nav-help"><a href="https://tomcat.apache.org/findhelp.html">Find Help</a></span>
                <br class="separator" />
            </div>
            <div id="asf-box">
                <h1>Apache Tomcat/X.X.XX</h1>
            </div>
            <div id="upper" class="curved container">
                <div id="congrats" class="curved container">
                    <h2>If you're seeing this, you've successfully installed Tomcat. Congratulations!</h2>
<SNIP>
```

**Questions**

Replicate the steps shown in this section to connect to the above server's "hidden" Tomcat page through the AJP proxy, then write the Tomcat version as your answer. Remember that the port you will see next to "Target:" will be the AJP proxy port. Answer format: X.X.XX

```bash
wget https://nginx.org/download/nginx-1.21.3.tar.gz
tar -xzvf nginx-1.21.3.tar.gz
git clone https://github.com/dvershinin/nginx_ajp_module.git
cd nginx-1.21.3
sudo apt install libpcre3-dev
./configure --add-module=`pwd`/../nginx_ajp_module --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib/nginx/modules
make
sudo make install
nginx -V
sudo vim /etc/nginx/conf/nginx.conf # replace server {}
upstream tomcats {
	server <TARGET_SERVER>:8009;
	keepalive 10;
	}
server {
	listen 80;
	location / {
		ajp_keep_conn on;
		ajp_pass tomcats;
	}

sudo nginx
curl http://127.0.0.1:80
#<title>Apache Tomcat/8.0.53</title>
```
