# Dynamic Port Forwarding with SSH and SOCKS Tunneling

### You have successfully captured credentials to an external facing Web Server. Connect to the target and list the network interfaces. How many network interfaces does the target web server have? (Including the loopback interface)

```bash
#SSH to 10.129.6.183 with user "ubuntu" and password "HTB_@cademy_stdnt!" 
ssh ubuntu@10.129.6.183  
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:71:4b brd ff:ff:ff:ff:ff:ff
    inet 10.129.6.183/16 brd 10.129.255.255 scope global dynamic ens192
       valid_lft 3491sec preferred_lft 3491sec
    inet6 dead:beef::250:56ff:feb9:714b/64 scope global dynamic mngtmpaddr 
       valid_lft 86400sec preferred_lft 14400sec
    inet6 fe80::250:56ff:feb9:714b/64 scope link 
       valid_lft forever preferred_lft forever
3: ens224: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:5a:79 brd ff:ff:ff:ff:ff:ff
    inet 172.16.5.129/23 brd 172.16.5.255 scope global ens224
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:feb9:5a79/64 scope link 
       valid_lft forever preferred_lft forever
```

3

### Apply the concepts taught in this section to pivot to the internal network and use RDP (credentials: victor:pass@123) to take control of the Windows target on 172.16.5.19. Submit the contents of Flag.txt located on the Desktop.

```bash
nmap -sT -p22,3306 10.129.6.183  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-25 11:37 EST
Nmap scan report for 10.129.6.183 (10.129.6.183)
Host is up (0.27s latency).

PORT     STATE  SERVICE
22/tcp   open   ssh
3306/tcp closed mysql
```

Executing the Local Port Forward

```bash
ssh -L 1234:localhost:3306 ubuntu@10.129.6.183
#Confirming Port Forward with Netstat
#in our kali
netstat -antp | grep 1234
#or
nmap -v -sV -p1234 localhost
```

Now for Enabling Dynamic Port Forwarding with SSH

```bash
ssh -D 9050 ubuntu@10.129.6.183
```

To inform proxychains that we must use port 9050, we must modify the proxychains configuration file located at `/etc/proxychains.conf`. We can add `socks4 127.0.0.1 9050` to the last line if it is not already there.

<pre class="language-bash"><code class="lang-bash">#Using Nmap with Proxychains
ifconfig #this on the target
<strong>proxychains nmap -v -sn 172.16.5.1-200 #this on our local machine
</strong>#[proxychains] Strict chain  ...  127.0.0.1:9050  ...  172.16.5.19:80  ...  OK
#Enumerating the Windows Target through Proxychains
proxychains nmap -v -Pn -sT 172.16.5.19
#Discovered open port 3389/tcp on 172.16.5.19
proxychains nmap -Pn -p3389 -sV -sC 172.16.5.19
proxychains nmap -Pn -p3389 -sV -sC 172.16.5.19
PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC01.inlanefreight.local
| Not valid before: 2024-02-24T16:32:39
|_Not valid after:  2024-08-25T16:32:39
|_ssl-date: 2024-02-25T16:55:47+00:00; +6s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: INLANEFREIGHT
|   NetBIOS_Domain_Name: INLANEFREIGHT
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: inlanefreight.local
|   DNS_Computer_Name: DC01.inlanefreight.local
|   Product_Version: 10.0.17763
|_  System_Time: 2024-02-25T16:55:42+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
</code></pre>

Using xfreerdp with Proxychains

```bash
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123 /cert-ignore /dynamic-resolution
N1c3Piv0t
```
