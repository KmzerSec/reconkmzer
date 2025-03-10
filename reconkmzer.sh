#!/bin/bash
################################################################################
# kmzersec - Automated Recon & Vulnerability Scanner
#
# This tool performs automated recon & vulnerability assessments on target domains
# by invoking many scanning tools to detect:
#
#   • Sensitive information exposure (passwords, API keys, credentials, tokens,
#     database files in repositories, etc.)
#   • Vulnerabilities (path traversal, 403 bypass, IDOR, CORS misconfigurations,
#     open redirect, CVE vulnerabilities, XSS, SQLi, subdomain takeover, etc.)
#
# The scan is designed to resume if interrupted. All output, configuration, and
# vulnerability reports are kept in the base folder "reconkmzer".
#
# Example usages:
#    Single domain:   ./kmzersec.sh -d example.com -w my_wordlist.txt
#    Domain list:     ./kmzersec.sh -dl domains.txt -w my_wordlist.txt
#
# Configuration:
#   Place a file "kmzersec.cfg" inside the "reconkmzer" folder to override default
#   settings (e.g., tool directories, output paths). Also create an "api_keys.txt"
#   file here to store your API keys (e.g., shodan=YOUR_SHODAN_API_KEY).
################################################################################

# ------------------ Base Directory Setup ---------------------
# All files, scans, reports, configs, etc. will reside in "reconkmzer"
BASE_DIR="$(pwd)/reconkmzer"
mkdir -p "$BASE_DIR"

# Default configuration file path and API key file inside BASE_DIR
CONFIG_FILE="$BASE_DIR/kmzersec.cfg"
API_KEYS_FILE="$BASE_DIR/api_keys.txt"

# Set default directories; these can be overridden in kmzersec.cfg
TOOLS_DIR="${TOOLS_DIR:-$HOME/tools}"
WORDLIST_DIR="${WORDLIST_DIR:-$BASE_DIR/wordlists}"
REPORTS_DIR="${REPORTS_DIR:-$BASE_DIR/reports}"
TMP_DIR="${TMP_DIR:-$BASE_DIR/tmp}"
mkdir -p "$WORDLIST_DIR" "$REPORTS_DIR" "$TMP_DIR"

# Checkpoint file for auto-resume
CHECKPOINT_FILE="$TMP_DIR/kmzersec_checkpoint.log"
[ ! -f "$CHECKPOINT_FILE" ] && touch "$CHECKPOINT_FILE"

# ------------------ Global Variables -------------------------
TARGETS=()
WORDLIST=""

# Colors for output messages
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

#########################
# Display Banner
#########################
print_banner() {
  clear
  cat << "EOF"
    __  __  _  __   ___   ______   ________
   |  \/  || |/ /  / _ \ | ___ \ \ / /  ___|
   | .  . || ' /  / /_\ \| |_/ /\ V /\ \__ \ 
   | |\/| ||  <   |  _  ||    /  \ /  ___) |
   | |  | || . \  | | | || |\ \  | | /____/  
   \_|  |_/_|\_\  \_| |_/\_| \_| \_/ \____/  
EOF
  echo -e "${YELLOW}kmzersec - Automated Recon & Vulnerability Scanner${NC}"
  echo -e "${YELLOW}For Bug Bounty & Authorized Penetration Testing Only${NC}"
  echo ""
}

#########################
# Usage Instructions
#########################
usage() {
  echo -e "Usage: $0 -d <domain> | -dl <domain_list_file> [-w <wordlist>] [-o <output_directory>]"
  echo -e "   -d      Single domain to scan (e.g., example.com)"
  echo -e "   -dl     File containing list of domains (one per line)"
  echo -e "   -w      Wordlist for directory scan (if omitted, a power wordlist is generated)"
  echo -e "   -o      Output directory override (default: ${REPORTS_DIR})"
  exit 1
}

#########################
# Load API Keys
#########################
load_api_keys() {
  if [ -f "$API_KEYS_FILE" ]; then
    echo -e "${GREEN}[+] Loaded API keys from $API_KEYS_FILE${NC}"
    while IFS='=' read -r key value; do
      if [[ -n "$key" && -n "$value" ]]; then
        echo "    $key : $value"
      fi
    done < "$API_KEYS_FILE"
  else
    echo -e "${YELLOW}[!] No API keys file found. Create $API_KEYS_FILE with your keys (e.g., shodan=YOUR_SHODAN_API_KEY).${NC}"
  fi
}

#########################
# Load External Config
#########################
if [ -f "$CONFIG_FILE" ]; then
  echo -e "${GREEN}[+] Loading configuration from $CONFIG_FILE${NC}"
  source "$CONFIG_FILE"
else
  echo -e "${YELLOW}[!] No config file found. Using default settings.${NC}"
fi

#########################
# Dependency Checker & Tools Updater
#########################
check_dependencies() {
  echo -e "${GREEN}[+] Checking required dependencies...${NC}"
  local deps=(whatweb gobuster nmap sqlmap nuclei amass subfinder curl python3)
  for dep in "${deps[@]}"; do
    if ! command -v "$dep" >/dev/null 2>&1; then
      echo -e "${RED}[!] Missing dependency: $dep. Please install it before running.${NC}"
      exit 1
    fi
  done
}

update_tools() {
  echo -e "${GREEN}[+] Updating tools...${NC}"
  if command -v nuclei >/dev/null 2>&1; then
    echo "[*] Updating nuclei templates..."
    nuclei -update-templates
  fi
  # You can add additional update routines here (ex: git pull for specific repositories)
}

#########################
# Auto-Resume Helpers
#########################
already_done() {
  local marker="$1"
  grep -Fxq "$marker" "$CHECKPOINT_FILE" && return 0 || return 1
}

save_checkpoint() {
  echo "$1" >> "$CHECKPOINT_FILE"
}

#########################
# Timer & Spinner Helpers
#########################
run_with_timer() {
  local desc="$1"
  shift
  echo -e "${GREEN}[*] Starting: $desc${NC}"
  local start=$(date +%s)
  "$@"
  local status=$?
  local end=$(date +%s)
  local runtime=$((end - start))
  echo -e "${GREEN}[*] Completed: $desc in ${runtime} seconds.${NC}"
  return $status
}

spinner() {
  local pid=$1
  local delay=0.1
  local spinstr='|/-\'
  while kill -0 "$pid" 2>/dev/null; do
    local temp=${spinstr#?}
    printf " [%c]  " "$spinstr"
    spinstr=$temp${spinstr%"$temp"}
    sleep $delay
    printf "\b\b\b\b\b\b"
  done
  printf "    \b\b\b\b"
}

#########################
# Wordlist Generation for Gobuster & Nmap
#########################
generate_power_wordlist() {
  local outfile="$WORDLIST_DIR/power_wordlist.txt"
  echo -e "${YELLOW}[*] No wordlist provided; generating a power wordlist at $outfile${NC}"
  cat <<EOF > "$outfile"
admin
login
dashboard
config
backup
old
test
dev
api
server-status
.htaccess
debug
EOF
  echo "$outfile"
}

#########################
# Recon Scan Functions
#########################

# 1. WhatWeb (always runs first)
run_whatweb() {
  local domain="$1"
  local out_dir="$2"
  local marker="whatweb_${domain}"
  if already_done "$marker"; then
    echo -e "${YELLOW}[!] WhatWeb scan already done for $domain. Skipping.${NC}"
    return
  fi
  run_with_timer "WhatWeb scan on $domain" whatweb "$domain" -v > "$out_dir/whatweb_${domain}.txt" 2>&1
  save_checkpoint "$marker"
}

# 2. Subdomain Enumeration (using subfinder and amass)
run_subdomain_enum() {
  local domain="$1"
  local out_dir="$2"
  local marker="subdomains_${domain}"
  if already_done "$marker"; then
    echo -e "${YELLOW}[!] Subdomain enumeration already done for $domain. Skipping.${NC}"
    return
  fi
  echo -e "${GREEN}[*] Running subdomain enumeration on $domain...${NC}"
  local sub_out="$out_dir/subdomains_${domain}.txt"
  subfinder -d "$domain" -silent > "$TMP_DIR/subfinder_${domain}.txt" 2>&1
  amass enum -d "$domain" -o "$TMP_DIR/amass_${domain}.txt" 2>&1
  cat "$TMP_DIR/subfinder_${domain}.txt" "$TMP_DIR/amass_${domain}.txt" 2>/dev/null | sort -u > "$sub_out"
  echo -e "${GREEN}[*] Subdomain results saved to $sub_out${NC}"
  save_checkpoint "$marker"
}

# 3. Directory Brute Force with Gobuster
run_directory_scan() {
  local domain="$1"
  local wordlist="$2"
  local out_dir="$3"
  local marker="gobuster_${domain}"
  if already_done "$marker"; then
    echo -e "${YELLOW}[!] Directory scan already done for $domain. Skipping.${NC}"
    return
  fi
  echo -e "${GREEN}[*] Running directory brute force on $domain using Gobuster...${NC}"
  run_with_timer "Gobuster scan on $domain" gobuster dir -u "http://$domain" -w "$wordlist" -t 50 -x php,html,js -q -o "$out_dir/gobuster_${domain}.txt"
  save_checkpoint "$marker"
}

# 4. Port Scan with Nmap (bypassing firewall with -Pn)
run_nmap_scan() {
  local domain="$1"
  local out_dir="$2"
  local marker="nmap_${domain}"
  if already_done "$marker"; then
    echo -e "${YELLOW}[!] Nmap scan already done for $domain. Skipping.${NC}"
    return
  fi
  echo -e "${GREEN}[*] Running Nmap scan on $domain using -Pn (firewall bypass)...${NC}"
  run_with_timer "Nmap scan on $domain" nmap -Pn -sS -T4 -A "$domain" -oN "$out_dir/nmap_${domain}.txt"
  save_checkpoint "$marker"
}

# 5. SQL Injection Testing with SQLMap (high-risk mode)
run_sqlmap_scan() {
  local domain="$1"
  local out_dir="$2"
  local marker="sqlmap_${domain}"
  if already_done "$marker"; then
    echo -e "${YELLOW}[!] SQLMap scan already done for $domain. Skipping.${NC}"
    return
  fi
  echo -e "${GREEN}[*] Running SQLMap in high mode on $domain...${NC}"
  # Modify this URL as needed for your target's testable endpoint.
  run_with_timer "SQLMap scan on $domain" sqlmap -u "http://$domain/vulnerable.php?id=1" --batch --level=5 --risk=3 --output-dir="$out_dir/sqlmap_${domain}"
  save_checkpoint "$marker"
}

# 6. Vulnerability Scanning with Nuclei (all severities)
run_nuclei_scan() {
  local domain="$1"
  local out_dir="$2"
  local marker="nuclei_${domain}"
  if already_done "$marker"; then
    echo -e "${YELLOW}[!] Nuclei scan already done for $domain. Skipping.${NC}"
    return
  fi
  echo -e "${GREEN}[*] Running Nuclei vulnerability scan on $domain...${NC}"
  run_with_timer "Nuclei scan on $domain" nuclei -u "$domain" -severity "critical,high,medium,low,info" -o "$out_dir/nuclei_${domain}.txt"
  save_checkpoint "$marker"
}

#########################
# Advanced Python Payload Tester Generator
#########################
generate_python_payload_tester() {
  local file="$BASE_DIR/advanced_payload_tester.py"
  if [ ! -f "$file" ]; then
    cat << 'EOF' > "$file"
#!/usr/bin/env python3
"""
advanced_payload_tester.py
Tests URL parameters for vulnerabilities (XSS, Path Traversal, SQLi,
Open Redirect, IDOR) using advanced payloads.
Extend this script as needed.
"""
import sys
import requests

payloads = {
    "xss": ["<script>alert(1)</script>", "\"'><svg/onload=alert(1)>"],
    "path_traversal": ["../../../../etc/passwd", "..\\..\\..\\..\\boot.ini"],
    "sqli": ["' OR '1'='1", "\" OR \"1\"=\"1"],
    "open_redirect": ["http://evil.com", "//evil.com"],
    "idor": ["1; DELETE FROM users"]
}

def test_payload(url, param, vuln_type):
    for payload in payloads.get(vuln_type, []):
        full_url = f"{url}?{param}={payload}"
        try:
            r = requests.get(full_url, timeout=10)
            print(f"[{vuln_type}] {full_url} => Status: {r.status_code}")
        except Exception as e:
            print(f"[{vuln_type}] Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: ./advanced_payload_tester.py <url> <parameter> <vulnerability_type>")
        sys.exit(1)
    url = sys.argv[1]
    param = sys.argv[2]
    vuln_type = sys.argv[3]
    test_payload(url, param, vuln_type)
EOF
    chmod +x "$file"
    echo -e "${GREEN}[+] Advanced Python payload tester created at: $file${NC}"
  fi
}

#########################
# HTML Report Aggregator
#########################
generate_html_report() {
  local report_file="$REPORTS_DIR/Recon_Report.html"
  echo -e "${GREEN}[*] Generating final HTML report...${NC}"
  {
    echo "<html><head><title>kmzersec Recon Report</title>"
    echo "<style>body { font-family: Arial; background: #f4f4f4; } h1 { text-align: center; } pre { background: #eee; padding: 10px; border: 1px solid #ccc; }</style>"
    echo "</head><body>"
    echo "<h1>kmzersec Recon Report</h1>"
    # Include all .txt files in REPORTS_DIR recursively in the HTML report.
    find "$REPORTS_DIR" -type f -name "*.txt" | while read -r file; do
      echo "<h2>$(basename "$file")</h2>"
      echo "<pre>$(< "$file")</pre>"
    done
    echo "</body></html>"
  } > "$report_file"
  echo -e "${GREEN}[+] HTML report generated at: $report_file${NC}"
}

#########################
# Main Execution
#########################
main() {
  print_banner

  # Load our configuration and API keys.
  [ -f "$CONFIG_FILE" ] && echo -e "${GREEN}[+] Loaded configuration from $CONFIG_FILE${NC}" || echo -e "${YELLOW}[!] No config file found, using defaults.${NC}"
  load_api_keys
  check_dependencies
  update_tools
  
  # Parse command-line options.
  while getopts ":d:dl:w:o:" opt; do
    case "$opt" in
      d)
        TARGETS+=("$OPTARG")
        ;;
      l)
        if [ -f "$OPTARG" ]; then
          while read -r line; do
            [ -n "$line" ] && TARGETS+=("$line")
          done < "$OPTARG"
        else
          echo -e "${RED}[!] Domain file '$OPTARG' not found.${NC}"
          exit 1
        fi
        ;;
      w)
        WORDLIST="$OPTARG"
        ;;
      o)
        REPORTS_DIR="$OPTARG"
        mkdir -p "$REPORTS_DIR"
        ;;
      *)
        usage
        ;;
    esac
  done
  
  # If no target domains are provided, show usage.
  [ ${#TARGETS[@]} -eq 0 ] && usage
  
  # Generate a power wordlist if one is not provided.
  if [ -z "$WORDLIST" ]; then
    WORDLIST=$(generate_power_wordlist)
  fi
  
  # Loop through each target domain.
  for domain in "${TARGETS[@]}"; do
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}[*] Processing target: $domain${NC}"
    echo -e "${GREEN}============================================${NC}"
    local target_out="$REPORTS_DIR/$domain"
    mkdir -p "$target_out"
    
    # Run scans in order. (WhatWeb MUST run first.)
    run_whatweb "$domain" "$target_out"
    run_subdomain_enum "$domain" "$target_out"
    run_directory_scan "$domain" "$WORDLIST" "$target_out"
    run_nmap_scan "$domain" "$target_out"
    run_sqlmap_scan "$domain" "$target_out"
    run_nuclei_scan "$domain" "$target_out"
    
    # Placeholder: Add additional tool invocations here (e.g., Aquatone, Nikto, Shodan, etc.)
    echo -e "${GREEN}[*] Finished processing target: $domain${NC}"
  done
  
  # Generate the aggregated HTML report and the advanced payload tester.
  generate_html_report
  generate_python_payload_tester
  
  echo -e "${GREEN}[*] All scans completed. Check your reports in ${REPORTS_DIR}${NC}"
  echo -e "${GREEN}[TIP] Customize tool parameters and extend with additional scanners or notifications for an even more robust recon setup.${NC}"
}

main "$@"

