#!/bin/bash

# Elite Dependencies
echo -e "\e[36m[+] Installing Cyber Arsenal\e[0m"
sudo apt update && sudo apt install -y golang python3-pip npm libimage-exiftool-perl ruby-dev libcurl4-openssl-dev

# AI Components
pip3 install torch transformers selenium beautifulsoup4 selenium-wire
gem install wayback_machine_downloader

# Install Elite Tools
GO_TOOLS=(
    "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
    "github.com/hakluke/hakrawler@latest"
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/jaeles-project/gospider@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/subjack/cmd/subjack@latest"
    "github.com/d3mondev/puredns/v2@latest"
)

for tool in "${GO_TOOLS[@]}"; do
    echo -e "\e[34mInstalling ${tool##*/}\e[0m"
    go install -v $tool
done

# Clone AI Modules
git clone https://github.com/kmzsec/ai-scanner $HOME/tools/ai_scanner
git clone https://github.com/kmzsec/report-gen $HOME/tools/report_gen

# Setup Elite Config
cat > kmzersec.cfg << EOF
# Elite Configuration
TOOLS_DIR="$HOME/tools"
WORDLIST_DIR="$HOME/wordlists"
REPORTS_DIR="\$(pwd)/reports"
TMP_DIR="\$(pwd)/tmp"

# API Keys (Enable with dark license key)
#SHODAN_API_KEY=""
#XSS_SERVER=""
#AI_MODEL="gpt-4-turbo"
EOF

echo -e "\n\e[32m[+] Elite Installation Complete!\e[0m"
echo "Initialize with: ./reconkmz.sh example.com"
