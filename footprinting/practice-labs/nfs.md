# NFS

### Enumerate the NFS service and submit the contents of the flag.txt in the "nfs" share as the answer.

```bash
sudo nmap -sV --script nfs* 10.129.132.231 -p111,2049
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-14 09:35 EST
Nmap scan report for 10.129.132.231 (10.129.132.231)
Host is up (0.27s latency).

PORT     STATE SERVICE VERSION
111/tcp  open  rpcbind 2-4 (RPC #100000)
|_rpcinfo: ERROR: Script execution failed (use -d to debug)
| nfs-showmount: 
|   /var/nfs 10.0.0.0/8
|_  /mnt/nfsshare 10.0.0.0/8
2049/tcp open  nfs     3-4 (RPC #100003)
```

or we can just **Show Available NFS Shares**

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ showmount -e 10.129.132.231
Export list for 10.129.132.231:
/var/nfs      10.0.0.0/8
/mnt/nfsshare 10.0.0.0/8
```

**Mounting NFS Share**

```bash
sudo mkdir /tmp/nfs
sudo mount -t nfs 10.129.132.231:/var/nfs /tmp/nfs -o nolock
cd /tmp/nfs
cat flag.txt
HTB{hjglmvtkjhlkfuhgi734zthrie7rjmdze}
```

### Enumerate the NFS service and submit the contents of the flag.txt in the "nfsshare" share as the answer.

```bash
sudo mkdir /tmp/nfsshare
sudo mount -t nfs 10.129.132.231:/mnt/nfsshare /tmp/nfsshare -o nolock
cd /tmp/nfsshare
cat flag.txt
HTB{8o7435zhtuih7fztdrzuhdhkfjcn7ghi4357ndcthzuc7rtfghu34}
```
