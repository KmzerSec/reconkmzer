#!/bin/bash
################################################################################
# ReconKmz - Automated Recon & Vulnerability Scanner
#
# This tool automates recon on one or more target domains by running a suite of
# scanners to uncover vulnerabilities such as:
#   • Sensitive data exposures (passwords, API keys, credentials, tokens, databases)
#   • Repository leaks & information disclosure
#   • Web vulnerabilities: path traversal, 403 bypass, IDOR, CORS issues, open 
#     redirects, CVE vulnerabilities, XSS, SQLi, subdomain takeover, etc.
#
# Scanning Phases (in order):
#
#    1. whatweb – Fingerprint target
#    2. Recon & Enumeration – (Assetfinder, Knockpy, CTFR & subdomain takeover)
#    3. Directory Fuzzing – (ffuf, wfuzz, dirsearch with dynamic power wordlists)
#    4. Vulnerability Testing – (SQLMap, Dalfox, XSStrike, Testssl.sh)
#    5. API/Secrets Discovery – (TruffleHog, SecretFinder, gitleaks, Shodan advanced scan)
#    6. Visual Recon – (Aquatone, Eyewitness, AutoRecon)
#    7. Severity-based Nuclei Scanning – (critical, high, medium, low, info)
#
# Features:
#   • Resume functionality so scans continue where they left off (if interrupted)
#   • Colorful banner and dynamic progress (percentage and time elapsed per step)
#   • HTML report generation for detailed vulnerability summaries
#   • “Power wordlist” generation for Gobuster and Nmap 
#
# Usage Options:
#   -d <domain>         Scan a single domain
#   -dl <file>          Scan multiple domains from a file (one domain per line)
#   -w                  Generate power wordlists for Gobuster and Nmap
#   --update            Update tools (e.g., nuclei templates)
#   --payload-tester    Generate a Python payload tester script
#   --install           Verify/install all required tools automatically (skips tools if already installed)
#
# Note: Edit configuration values below (or via the kmzersec.cfg file).
#
# Aquatone Installation on Kali Linux:
#   1. Download the latest release from:
#      https://github.com/michenriksen/aquatone/releases/
#   2. Unzip the file (e.g., unzip aquatone_linux_amd64_1.7.0.zip)
#   3. Move the binary to /usr/bin/:
#      sudo mv aquatone /usr/bin/
#
# XSStrike Installation:
#   • This script installs XSStrike using pipx (ensure pipx is installed).
################################################################################

# Configuration
CONFIG_FILE="kmzersec.cfg"
TOOLS_DIR="$HOME/tools"
WORDLIST_DIR="$HOME/wordlists"
REPORTS_DIR="$(pwd)/reports"
TMP_DIR="$(pwd)/tmp"

# APIs/TOKENS - Uncomment and set:
#SHODAN_API_KEY="XXXXXXXXXXXXX"
#WHOISXML_API="XXXXXXXXXX"
#XSS_SERVER="XXXXXXXXXXXXXXXXX"

# Create necessary directories if not exist
mkdir -p "$TOOLS_DIR" "$WORDLIST_DIR" "$REPORTS_DIR" "$TMP_DIR"

################################################################################
# Color Codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

################################################################################
# Print Banner: ReconKmz
print_banner() {
cat << "EOF"
 ____  _____ ____ ___  _   _ _  ____  __ _________  
|  _ \| ____/ ___/ _ \| \ | | |/ /  \/  |__  /  _ \ 
| |_) |  _|| |  | | | |  \| | ' /| |\/| | / /| |_) |
|  _ <| |__| |__| |_| | |\  | . \| |  | |/ /_|  _ < 
|_| \_\_____\____\___/|_| \_|_|\_\_|  |_/____|_| \_\
EOF
  echo -e "${CYAN}           ReconKmz - Automated Recon & Vuln Scanner${NC}"
  echo -e "${GREEN}   Advanced recon scanning for bug bounty & security testing${NC}"
  echo -e "${CYAN}===================================================================${NC}"
  echo -e "${YELLOW}[*] Welcome to ReconKmz${NC}"
  echo -e "${GREEN}[*] Tip: Configure API keys in ${CONFIG_FILE} and update tools with --update${NC}"
  echo -e "${CYAN}===================================================================${NC}"
}
print_banner

################################################################################
# Usage instructions
usage() {
    echo "Usage:"
    echo "  $0 -d <domain>         # Scan a single domain"
    echo "  $0 -dl <domains_file>  # Scan multiple domains (one per line)"
    echo "  $0 -w                  # Generate power wordlists for gobuster and nmap"
    echo "  $0 --update            # Update tools (e.g., nuclei templates)"
    echo "  $0 --payload-tester    # Create a Python payload tester script"
    echo "  $0 --install           # Install all required tools automatically"
    exit 1
}

################################################################################
# Check and install required tools.
# For xsstrike, install via pipx.
check_tool() {
    local tool=$1
    if [[ "$tool" == "xsstrike" ]]; then
        if ! command -v xsstrike &>/dev/null; then
            echo -e "${RED}[-] xsstrike not found. Installing via pipx...${NC}"
            if ! command -v pipx &>/dev/null; then
                echo -e "${RED}[-] pipx is required for installing xsstrike. Install pipx (e.g., pip install pipx) and try again.${NC}"
                exit 1
            fi
            pipx install xsstrike
            if ! command -v xsstrike &>/dev/null; then
                echo -e "${RED}[-] xsstrike installation via pipx failed. Install manually.${NC}"
                exit 1
            fi
            echo -e "${GREEN}[+] xsstrike installed successfully via pipx.${NC}"
        fi
    else
        if ! command -v "$tool" &>/dev/null; then
            echo -e "${RED}[-] $tool not found. Attempting installation via apt-get...${NC}"
            sudo apt-get install -y "$tool" && echo -e "${GREEN}[+] $tool installed.${NC}" || {
                echo -e "${RED}[-] Could not install $tool. Please install manually.${NC}"
                exit 1
            }
        fi
    fi
}

install_requirements() {
    echo -e "${GREEN}[*] Checking and installing required tools...${NC}"
    local required_tools=( "whatweb" "assetfinder" "knockpy" "ffuf" "wfuzz" "dirsearch" "sqlmap" "dalfox" "xsstrike" "testssl.sh" "trufflehog" "aquatone" "eyewitness" "autorecon" "nuclei" )
    for tool in "${required_tools[@]}"; do
        check_tool "$tool"
    done
}

################################################################################
# Option --install: Install all required tools and exit.
if [[ "$1" == "--install" ]]; then
    install_requirements
    echo -e "${GREEN}[+] All required tools are installed.${NC}"
    exit 0
fi

################################################################################
# Resume handling: record completed steps in a resume log per target.
is_step_done() {
    local target=$1
    local step=$2
    [[ -f "$TMP_DIR/${target}_resume.log" ]] && grep -q "^step${step}$" "$TMP_DIR/${target}_resume.log"
}

mark_step_done() {
    local target=$1
    local step=$2
    echo "step${step}" >> "$TMP_DIR/${target}_resume.log"
}

################################################################################
# Run an individual scanning step with progress, timer, and resume logic.
run_step() {
    local step=$1
    local desc="$2"
    local cmd="$3"
    local target=$4

    if is_step_done "$target" "$step"; then
        echo -e "[${YELLOW}*${NC}] Step $step: '$desc' already completed. Skipping."
        return 0
    fi

    local progress=$(( (step - 1) * 100 / total_steps ))
    echo "------------------------------------------------------------"
    echo -e "[*] Progress: ${progress}%  | Running Step $step: $desc"
    local start_time=$(date +%s)
    
    eval "$cmd"
    local ret=$?
    local end_time=$(date +%s)
    local elapsed=$(( end_time - start_time ))
    
    if [[ $ret -eq 0 ]]; then
         echo -e "[+] Step $step completed in $elapsed seconds."
         mark_step_done "$target" "$step"
    else
         echo -e "${RED}[-] Step $step encountered an error (exit code $ret).${NC}"
    fi
}

################################################################################
# Generate consolidated HTML report for a target.
generate_html_report() {
    local target=$1
    local target_folder="$REPORTS_DIR/$target"
    local report_file="$target_folder/report.html"
    
    echo "[*] Generating HTML report for $target..."
    {
        echo "<html><head>"
        echo "  <title>ReconKmz Report for $target</title>"
        echo "  <style>"
        echo "    body { font-family: Arial, sans-serif; background-color: #f4f4f4; }"
        echo "    pre { background-color: #eaeaea; padding: 10px; border: 1px solid #ccc; }"
        echo "    h1, h2, h3 { color: #333; }"
        echo "  </style>"
        echo "</head><body>"
        echo "  <h1>ReconKmz Report for $target</h1>"
        echo "  <h2>Scan Details</h2>"
        for file in "$target_folder"/*.txt; do
            [ -e "$file" ] || continue
            echo "  <h3>$(basename "$file")</h3>"
            echo "  <pre>"
            cat "$file"
            echo "  </pre><hr>"
        done
        echo "</body></html>"
    } > "$report_file"
    echo "[+] Report generated: $report_file"
}

################################################################################
# Generate “power wordlists” for Gobuster and Nmap.
generate_wordlists() {
    echo "[*] Generating Power Wordlists..."
    local gobuster_wordlist="$WORDLIST_DIR/gobuster_power.txt"
    local nmap_wordlist="$WORDLIST_DIR/nmap_power.txt"
    
    if [[ -f /usr/share/wordlists/dirb/common.txt ]]; then
        cat /usr/share/wordlists/dirb/common.txt > "$gobuster_wordlist"
        cp "$gobuster_wordlist" "$nmap_wordlist"
        echo "[+] Generated wordlists:"
        echo "    Gobuster: $gobuster_wordlist"
        echo "    Nmap:     $nmap_wordlist"
    else
        echo "[-] Default wordlist not found. Please populate $WORDLIST_DIR manually."
    fi
}

################################################################################
# Prepare output folder for a target.
prepare_target_folder() {
    local target=$1
    local target_folder="$REPORTS_DIR/$target"
    mkdir -p "$target_folder"
    echo "$target_folder"
}

################################################################################
# Update tools (e.g. update nuclei templates).
update_tools() {
    echo "[*] Updating tools..."
    nuclei -update-templates && echo "[+] Nuclei templates updated."
    # Further update commands can be added here.
}

################################################################################
# Total scanning phases (update if adding more steps)
total_steps=7

################################################################################
# Scan a single domain: Run each scanning phase.
scan_domain() {
    local target=$1
    echo "============================================================"
    echo "[*] Starting scan for target: $target"
    local target_folder
    target_folder=$(prepare_target_folder "$target")
    echo "[*] Scan outputs will be stored in: $target_folder"

    # Phase 1: whatweb (fingerprint)
    run_step 1 "whatweb – Fingerprint Target" "whatweb -v \"$target\" > \"$target_folder/whatweb.txt\"" "$target"

    # Phase 2: Recon & Enumeration (assetfinder, knockpy, CTFR/subdomain takeover)
    run_step 2 "Recon & Enumeration" \
       "assetfinder --subs-only \"$target\" > \"$target_folder/assetfinder.txt\"; \
        knockpy \"$target\" -o \"$target_folder/knockpy.txt\"" "$target"

    # Phase 3: Directory Fuzzing (ffuf, wfuzz, dirsearch using power wordlists)
    run_step 3 "Directory Fuzzing" \
       "ffuf -u \"$target/FUZZ\" -w \"$WORDLIST_DIR/gobuster_power.txt\" -o \"$target_folder/ffuf.txt\"; \
        wfuzz -c -z file,\"$WORDLIST_DIR/gobuster_power.txt\" -u \"$target/FUZZ\" --hc 404 > \"$target_folder/wfuzz.txt\"; \
        dirsearch -u \"$target\" -w \"$WORDLIST_DIR/gobuster_power.txt\" -e * -o \"$target_folder/dirsearch.txt\"" "$target"

    # Phase 4: Vulnerability Testing (SQLMap, Dalfox, XSStrike, Testssl.sh)
    run_step 4 "Vulnerability Testing" \
       "sqlmap -u \"$target\" --batch --level=5 --risk=3 > \"$target_folder/sqlmap.txt\"; \
        dalfox url \"$target\" -w \"$WORDLIST_DIR/gobuster_power.txt\" -o \"$target_folder/dalfox.txt\"; \
        xsstrike -u \"$target\" --crawl > \"$target_folder/xsstrike.txt\"; \
        testssl.sh \"$target\" > \"$target_folder/testssl.txt\"" "$target"

    # Phase 5: API/Secrets Discovery (TruffleHog, optional advanced Shodan scan)
    run_step 5 "API/Secrets Discovery" \
       "trufflehog --regex --entropy=True \"$target\" > \"$target_folder/trufflehog.txt\"; \
        if [[ ! -z \"$SHODAN_API_KEY\" ]]; then \
           shodan search --fields ip_str,port,org,hostnames \"http.title:$target\" > \"$target_folder/shodan.txt\"; \
        fi" "$target"

    # Phase 6: Visual Recon (Aquatone, Eyewitness, AutoRecon)
    run_step 6 "Visual Recon" \
       "aquatone -scan \"$target\" > \"$target_folder/aquatone.txt\"; \
        eyewitness --web -f \"$target\" -d \"$target_folder/eyewitness\"; \
        autorecon -t \"$target\" > \"$target_folder/autorecon.txt\"" "$target"

    # Phase 7: Severity-based Nuclei Scanning
    run_step 7 "Nuclei – Severity-based Scanning" \
       "nuclei -u \"$target\" -severity critical,high,medium,low,info -o \"$target_folder/nuclei.txt\"" "$target"

    # Generate consolidated HTML report
    generate_html_report "$target"
    echo "[*] Scan completed for $target"
    echo "============================================================"
}

################################################################################
# Scan multiple domains from a file (one per line).
scan_domains_from_file() {
    local file=$1
    if [[ ! -f "$file" ]]; then
        echo "[-] Domain list file not found: $file"
        exit 1
    fi
    while IFS= read -r domain; do
        [[ -z "$domain" || "$domain" =~ ^# ]] && continue
        scan_domain "$domain"
    done < "$file"
}

################################################################################
# Create a Python payload tester script (advanced payloads for XSS, SQLi, etc.)
create_payload_tester() {
cat << 'EOF' > payload_tester.py
#!/usr/bin/env python3
"""
Payload Tester Script

This tool tests a target URL and parameter with advanced payloads for:
  • XSS
  • SQL Injection
  • Path Traversal
  • Open Redirect
  • IDOR vulnerabilities

Usage:
  python3 payload_tester.py --url <target_url> --param <parameter_name>
"""
import argparse
import requests

payloads = {
    "XSS": ['<script>alert(1)</script>', '"><svg/onload=alert(1)>'],
    "SQLi": ["' OR '1'='1", "\" OR \"1\"=\"1", "' OR '1'='1' -- "],
    "PathTraversal": ['../../../../etc/passwd', '../' * 10 + 'etc/passwd'],
    "OpenRedirect": ['http://evil.com', '//evil.com'],
    "IDOR": ['1', '0']
}

def test_payload(url, param, payload):
    try:
        params = {param: payload}
        r = requests.get(url, params=params, timeout=10)
        print(f"Payload: {payload[:30]}... | Status: {r.status_code}")
    except Exception as e:
        print(f"Error with payload {payload}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Payload Tester")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--param", required=True, help="Parameter name to test")
    args = parser.parse_args()
    for vuln_type, payload_list in payloads.items():
        print(f"--- Testing {vuln_type} Payloads ---")
        for pl in payload_list:
            test_payload(args.url, args.param, pl)
        print("=" * 50)
EOF
chmod +x payload_tester.py
echo "[*] Python payload tester created: payload_tester.py"
}

################################################################################
# Process command-line arguments.
if [[ $# -eq 0 ]]; then
    usage
fi

while [[ $# -gt 0 ]]; do
    case $1 in
        -d)
            if [[ -z "$2" ]]; then
                echo "[-] Please provide a domain."
                usage
            fi
            scan_domain "$2"
            shift 2
            ;;
        -dl)
            if [[ -z "$2" ]]; then
                echo "[-] Please provide a file containing domains."
                usage
            fi
            scan_domains_from_file "$2"
            shift 2
            ;;
        -w)
            generate_wordlists
            shift
            ;;
        --update)
            update_tools
            shift
            ;;
        --payload-tester)
            create_payload_tester
            shift
            ;;
        *)
            usage
            ;;
    esac
done

echo "=================================================================="
echo -e "[${GREEN}+${NC}] ReconKmz scanning completed."
echo "[*] Final reports are located in: $REPORTS_DIR"
