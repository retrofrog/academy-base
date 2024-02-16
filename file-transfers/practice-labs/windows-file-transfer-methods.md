# Windows File Transfer Methods

### Download the file flag.txt from the web root using wget from the Pwnbox. Submit the contents of the file as your answer.

```bash
wget 10.129.201.55/flag.txt
cat flag.txt 
b1a4ca918282fcd96004565521944a3b 
```

### Upload the attached file named upload\_win.zip to the target using the method of your choice. Once uploaded, RDP to the box, unzip the archive, and run "hasher upload\_win.txt" from the command line. Submit the generated hash as your answer.

```bash
#this is via smb
#on linux side
impacket-smbserver share -smb2support /tmp/share -user doge -password doge
#on win
net use n: \\192.168.220.133\share /user:test test
copy n:\nc.exe
```

```bash
#WebDav Server
sudo pip install wsgidav cheroot
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous 
#on windows
dir \\192.168.49.128\DavWWWRoot
```
