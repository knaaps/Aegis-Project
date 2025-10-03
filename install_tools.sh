#!/bin/bash
echo "Installing security tools for Aegis-Lite..."

# Install Subfinder
wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.tar.gz
tar -xzf subfinder_2.6.3_linux_amd64.tar.gz
sudo mv subfinder /usr/local/bin/
rm subfinder_2.6.3_linux_amd64.tar.gz

# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

echo "Tools installed successfully!"