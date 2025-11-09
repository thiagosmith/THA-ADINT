#!/bin/bash

echo "🔧 Parando serviços do Wazuh..."
sudo systemctl stop wazuh-manager wazuh-indexer wazuh-dashboard 2>/dev/null

echo "🧨 Removendo arquivos de controle do pacote quebrado..."
sudo rm -f /var/lib/dpkg/info/wazuh-manager.*

echo "🧹 Forçando remoção do pacote wazuh-manager..."
sudo dpkg --remove --force-remove-reinstreq wazuh-manager

echo "🧽 Limpando diretórios residuais..."
sudo rm -rf /var/ossec /etc/wazuh* /var/lib/wazuh* /var/log/wazuh*

echo "🔄 Corrigindo pacotes quebrados..."
sudo apt --fix-broken install -y

echo "⬇️ Baixando script oficial do Wazuh 4.14..."
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh

echo "🚀 Iniciando nova instalação do Wazuh 4.14..."
sudo bash ./wazuh-install.sh --all-in-one --ignore-check --overwrite
