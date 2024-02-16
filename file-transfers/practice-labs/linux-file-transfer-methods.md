# Linux File Transfer Methods

### Download the file flag.txt from the web root using Python from the Pwnbox. Submit the contents of the file as your answer.

```bash
#wget
wget http://10.129.115.51/flag.txt -O /tmp/flag.txt
#curl
curl -o /tmp/flag.txt http://10.129.115.51/flag.txt
```

### Upload the attached file named upload\_nix.zip to the target using the method of your choice. Once uploaded, SSH to the box, extract the file, and run "hasher " from the command line. Submit the generated hash as your answer.

```bash
python3 -m http.server 8000
wget 192.168.49.128:8000/upload_nix.zip
```
