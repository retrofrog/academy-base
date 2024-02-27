# SSH Pivoting with Sshuttle

Try using sshuttle from Pwnbox to connect via RDP to the Windows target (172.16.5.19) with "victor:pass@123" on the internal network. Once completed type: "I tried sshuttle" as the answer.

```bash
#user "ubuntu" and password "HTB_@cademy_stdnt!" 
ssh ubuntu@10.129.31.240
ifconfig
#inet 172.16.5.129  netmask 255.255.254.0  broadcast 172.16.5.255
sudo sshuttle -r ubuntu@10.129.31.240 172.16.5.0/23 -v
nmap -v -sV -p3389 172.16.5.19 -A -Pn
```
