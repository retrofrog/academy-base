# Port Forwarding with Windows Netsh

[Netsh](https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts) is a Windows command-line tool that can help with the network configuration of a particular Windows system. Here are just some of the networking related tasks we can use `Netsh` for:

* `Finding routes`
* `Viewing the firewall configuration`
* `Adding proxies`
* `Creating port forwarding rules`

Let's take an example of the below scenario where our compromised host is a Windows 10-based IT admin's workstation (`10.129.15.150`,`172.16.5.25`). Keep in mind that it is possible on an engagement that we may gain access to an employee's workstation through methods such as social engineering and phishing. This would allow us to pivot further from within the network the workstation is in.

![](https://academy.hackthebox.com/storage/modules/158/88.png)

We can use `netsh.exe` to forward all data received on a specific port (say 8080) to a remote host on a remote port. This can be performed using the below command.

**Using Netsh.exe to Port Forward**

Port Forwarding with Windows Netsh

```cmd-session
C:\Windows\system32> netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```

**Verifying Port Forward**

Port Forwarding with Windows Netsh

```cmd-session
C:\Windows\system32> netsh.exe interface portproxy show v4tov4

Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
10.129.42.198   8080        172.16.5.25     3389
```

After configuring the `portproxy` on our Windows-based pivot host, we will try to connect to the 8080 port of this host from our attack host using xfreerdp. Once a request is sent from our attack host, the Windows host will route our traffic according to the proxy settings configured by netsh.exe.

**Connecting to the Internal Host through the Port Forward**

![](https://academy.hackthebox.com/storage/modules/158/netsh\_pivot.png)

***

Note: When spawning your target, we ask you to wait for 3 - 5 minutes until the whole lab with all the configurations is set up so that the connection to your target works flawlessly.
