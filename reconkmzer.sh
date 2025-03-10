#!/bin/bash
# Reconkmz - Advanced Recon & Vulnerability Scanner (Enhanced Advanced Modules)
# Version 3.5 Final
#
# This script concurrently runs multiple scan modules.
#
# Basic Modules:
#   • --info         Basic Information Disclosure Scan
#   • --sensitive    Basic Sensitive Data Scan
#   • --cors         Basic CORS Scan
#   • --xss          Basic XSS Scan
#   • --adv          Advanced Scan (Nmap, Nikto, Gobuster)
#   • --nuclei       Persistent Nuclei Scan (with resume support)
#   • --shodan       Basic Shodan Scan
#   • --cve          CVE Scan (using searchsploit)
#   • --apikey       Basic API Key Scan
#   • --cred         Credential File Scan (sensitive file extensions)
#   • --openredirect Basic Open Redirect Scan
#   • --xssadv       Advanced XSS Scan (powerful payloads, parameter fuzzing)
#
# Advanced Modules:
#   • --infoadv      Advanced Information Disclosure Scan
#   • --sensadv      Advanced Sensitive Data Exposure Scan
#   • --apikeyadv    Advanced API Key Scan
#   • --shodanadv    Advanced Shodan Scan
#   • --redirectadv  Advanced Open Redirect Scan
#
# External configuration is loaded from kmzersec.cfg.
CONFIG_FILE="kmzersec.cfg"
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
fi

# Set RESULTS_DIR (default is "$PWD/Reconkmz")
RESULTS_DIR="${REPORTS_DIR:-$PWD/Reconkmz}"
mkdir -p "$RESULTS_DIR"

# Optional environment variables (NUCLEI_TEMPLATE_DIR, API_VALIDATE_URL, SHODAN_API_KEY, etc.) can also be set in kmzersec.cfg.
#
# DISCLAIMER: Only scan systems you are authorized to test.

#############################
#      UTILITY FUNCTIONS    #
#############################

# URL-encode a string (requires Python 3).
urlencode() {
  python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1]))" "$1"
}

# Write progress percentage (0-100) for a module.
update_progress() {
  local mod="$1"
  local prog="$2"
  echo "$prog" > /tmp/reconkmz-${mod}.progress
}

# Generate a 20-character wide ASCII progress bar.
progress_bar() {
  local prog=$1
  local total=20
  local filled=$(( prog * total / 100 ))
  local empty=$(( total - filled ))
  local bar=""
  for ((i=0; i<filled; i++)); do
    bar="${bar}#"
  done
  for ((i=0; i<empty; i++)); do
    bar="${bar}-"
  done
  echo "[$bar]"
}

#############################
#         BANNER            #
#############################
print_banner() {
cat << "EOF"
 ____                      _  __              
|  _ \ ___  ___ ___  _ __ | |/ /_ __ ___  ____
| |_) / _ \/ __/ _ \| '_ \| ' /| '_ ` _ \|_  /
|  _ <  __/ (_| (_) | | | | . \| | | | | |/ / 
|_| \_\___|\___\___/|_| |_|_|\_\_| |_| |_/___|

         Reconkmz - Advanced Recon & Vulnerability Scanner
-----------------------------------------------------------------
DISCLAIMER: Only scan systems you are authorized to test.
EOF
}

#############################
#      PROGRESS MONITOR     #
#############################
monitor_progress() {
  local mods=()
  [ "$flag_info" -eq 1 ]      && mods+=( "info" )
  [ "$flag_infoadv" -eq 1 ]   && mods+=( "infoadv" )
  [ "$flag_sensitive" -eq 1 ] && mods+=( "sensitive" )
  [ "$flag_sensadv" -eq 1 ]   && mods+=( "sensadv" )
  [ "$flag_cors" -eq 1 ]      && mods+=( "cors" )
  [ "$flag_xss" -eq 1 ]       && mods+=( "xss" )
  [ "$flag_adv" -eq 1 ]       && mods+=( "adv" )
  [ "$flag_nuclei" -eq 1 ]    && mods+=( "nuclei" )
  [ "$flag_shodan" -eq 1 ]    && mods+=( "shodan" )
  [ "$flag_shodanadv" -eq 1 ] && mods+=( "shodanadv" )
  [ "$flag_cve" -eq 1 ]       && mods+=( "cve" )
  [ "$flag_apikey" -eq 1 ]    && mods+=( "apikey" )
  [ "$flag_apikeyadv" -eq 1 ] && mods+=( "apikeyadv" )
  [ "$flag_cred" -eq 1 ]      && mods+=( "cred" )
  [ "$flag_redirect" -eq 1 ]  && mods+=( "redirect" )
  [ "$flag_redirectadv" -eq 1 ] && mods+=( "redirectadv" )
  [ "$flag_xssadv" -eq 1 ]    && mods+=( "xssadv" )
  
  while true; do
    local tot=0 count=0
    for m in "${mods[@]}"; do
      local prog
      prog=$(cat "/tmp/reconkmz-${m}.progress" 2>/dev/null || echo 0)
      tot=$(( tot + prog ))
      count=$(( count + 1 ))
    done
    local overall=0
    [ $count -gt 0 ] && overall=$(( tot / count ))
    clear
    echo "-------------------------------"
    echo "   Reconkmz Progress Dashboard"
    echo "-------------------------------"
    for m in "${mods[@]}"; do
      local prog label
      prog=$(cat "/tmp/reconkmz-${m}.progress" 2>/dev/null || echo 0)
      case "$m" in
        info)         label="Basic Info Disclosure:" ;;
        infoadv)      label="Advanced Info Disclosure:" ;;
        sensitive)    label="Basic Sensitive Data:" ;;
        sensadv)      label="Advanced Sensitive Data:" ;;
        cors)         label="Basic CORS Scan:" ;;
        xss)          label="Basic XSS Scan:" ;;
        adv)          label="Advanced Scan:" ;;
        nuclei)       label="Nuclei Scan:" ;;
        shodan)       label="Basic Shodan Scan:" ;;
        shodanadv)    label="Advanced Shodan Scan:" ;;
        cve)          label="CVE Scan:" ;;
        apikey)       label="Basic API Key Scan:" ;;
        apikeyadv)    label="Advanced API Key Scan:" ;;
        cred)         label="Credential File Scan:" ;;
        redirect)     label="Basic Open Redirect Scan:" ;;
        redirectadv)  label="Advanced Open Redirect Scan:" ;;
        xssadv)       label="Advanced XSS Scan:" ;;
         *)           label="$m:" ;;
      esac
      printf "%-28s %3d%% %s\n" "$label" "$prog" "$(progress_bar "$prog")"
    done
    printf "\nOverall Progress:      %3d%% %s\n" "$overall" "$(progress_bar "$overall")"
    [ "$overall" -eq 100 ] && break
    sleep 1
  done
}

#############################
#  BASIC INFO DISCLOSURE Scan
#############################
info_disclosure_scan() {
  update_progress info 0
  echo "[*] Starting Basic Information Disclosure Scan..."
  local endpoints=( ".git/config" "config.php" ".env" "backup.zip" "admin/" "test/" "config.yaml" "db_backup.sql" )
  local total=${#endpoints[@]} count=0
  for ep in "${endpoints[@]}"; do
    local url
    if [[ "$target" =~ /$ ]]; then
      url="$target$ep"
    else
      url="$target/$ep"
    fi
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" "$url")
    if [ "$code" == "200" ]; then
      echo "[+] Found accessible endpoint: $url (HTTP $code)"
    else
      echo "[-] $url returned HTTP $code"
    fi
    count=$(( count + 1 ))
    local prog=$(( count * 100 / total ))
    update_progress info "$prog"
  done
  update_progress info 100
  echo "[-] Basic Information Disclosure Scan completed."
  echo
}

#############################
# ADVANCED INFO DISCLOSURE Scan
#############################
advanced_info_disclosure_scan() {
  update_progress infoadv 0
  echo "[*] Starting Advanced Information Disclosure Scan..."
  local endpoints=( 
    ".git/config" "config.php" ".env" "backup.zip" "admin/" "test/" "config.yaml" "db_backup.sql" 
    "robots.txt" "sitemap.xml" "backup.tar.gz" "backup.zip" "backup.sql"
  )
  local total=${#endpoints[@]} count=0
  # Create/clear output file.
  > "$RESULTS_DIR/infoadv_scan.txt"
  for ep in "${endpoints[@]}"; do
    local url
    if [[ "$target" =~ /$ ]]; then
      url="$target$ep"
    else
      url="$target/$ep"
    fi
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" "$url")
    if [ "$code" == "200" ]; then
      echo "[+] $url (HTTP $code)" | tee -a "$RESULTS_DIR/infoadv_scan.txt"
      # Optionally check content.
      local content
      content=$(curl -s "$url")
      if echo "$content" | grep -Ei "password|secret|key|confidential" >/dev/null; then
        echo "[!] Sensitive content detected in: $url" | tee -a "$RESULTS_DIR/infoadv_scan.txt"
      fi
    else
      echo "[-] $url (HTTP $code)" >> "$RESULTS_DIR/infoadv_scan.txt"
    fi
    count=$(( count + 1 ))
    local prog=$(( count * 100 / total ))
    update_progress infoadv "$prog"
  done
  update_progress infoadv 100
  echo "[-] Advanced Information Disclosure Scan completed."
  echo
}

#############################
#  BASIC SENSITIVE DATA Scan
#############################
sensitive_data_scan() {
  update_progress sensitive 0
  echo "[*] Starting Basic Sensitive Data Exposure Scan..."
  local content
  content=$(curl -s "$target")
  local keywords=( "access_token" "client_secret" "private_key" "db_pass" "password" "secret" "confidential" )
  local total=${#keywords[@]} count=0 found=0
  for kw in "${keywords[@]}"; do
    if echo "$content" | grep -qi "$kw"; then
      echo "[+] Detected keyword: $kw" 
      found=1
    fi
    count=$(( count + 1 ))
    local prog=$(( count * 100 / total ))
    update_progress sensitive "$prog"
  done
  [ "$found" -eq 0 ] && echo "[-] No basic sensitive data found."
  update_progress sensitive 100
  echo "[-] Basic Sensitive Data Scan completed."
  echo
}

#############################
# ADVANCED SENSITIVE DATA Scan
#############################
advanced_sensitive_data_scan() {
  update_progress sensadv 0
  echo "[*] Starting Advanced Sensitive Data Exposure Scan..."
  # Extend scan to additional common pages.
  local pages=("$target" "$target/login" "$target/admin" "$target/dashboard")
  local keywords=( "password" "secret" "api_key" "token" "credential" "confidential" )
  local total=$(( ${#pages[@]} * ${#keywords[@]} ))
  local scanned=0 found=0
  > "$RESULTS_DIR/sensadv_scan.txt"
  for page in "${pages[@]}"; do
    local content
    content=$(curl -s "$page")
    for kw in "${keywords[@]}"; do
      if echo "$content" | grep -qi "$kw"; then
        echo "[+] '$kw' detected on $page" | tee -a "$RESULTS_DIR/sensadv_scan.txt"
        found=1
      fi
      scanned=$(( scanned + 1 ))
      local prog=$(( scanned * 100 / total ))
      update_progress sensadv "$prog"
    done
  done
  [ "$found" -eq 0 ] && echo "[-] No advanced sensitive data found." >> "$RESULTS_DIR/sensadv_scan.txt"
  update_progress sensadv 100
  echo "[-] Advanced Sensitive Data Exposure Scan completed."
  echo
}

#############################
#     BASIC CORS SCAN
#############################
cors_scan() {
  update_progress cors 0
  echo "[*] Starting Basic CORS Scan..."
  sleep 0.5
  local origin_response
  origin_response=$(curl -s -I -H "Origin: http://evil.com" "$target")
  if echo "$origin_response" | grep -qi "Access-Control-Allow-Origin:"; then
    echo "[+] Basic CORS header detected."
  else
    echo "[-] No CORS header detected."
  fi
  update_progress cors 100
  echo "[-] Basic CORS Scan completed."
  echo
}

#############################
#   ADVANCED CORS SCAN
#############################
advanced_cors_scan() {
  update_progress corsadv 0
  echo "[*] Starting Advanced CORS Vulnerability Scan..."
  local origins=("http://evil.com" "null" "http://attacker.com")
  local vulnerabilities=0 total=${#origins[@]} count=0
  > "$RESULTS_DIR/corsadv_scan.txt"
  for origin in "${origins[@]}"; do
    echo "[*] Testing with Origin: $origin" | tee -a "$RESULTS_DIR/corsadv_scan.txt"
    local headers
    headers=$(curl -s -I -H "Origin: $origin" "$target")
    if echo "$headers" | grep -qi "\*"; then
      echo "[!] Insecure: Wildcard '*' returned for Origin $origin" | tee -a "$RESULTS_DIR/corsadv_scan.txt"
      vulnerabilities=$(( vulnerabilities + 1 ))
    elif echo "$headers" | grep -qi "$origin"; then
      echo "[!] Insecure Reflection: $origin allowed" | tee -a "$RESULTS_DIR/corsadv_scan.txt"
      vulnerabilities=$(( vulnerabilities + 1 ))
    else
      echo "[*] Origin $origin appears safe." | tee -a "$RESULTS_DIR/corsadv_scan.txt"
    fi
    count=$(( count + 1 ))
    local prog=$(( count * 100 / total ))
    update_progress corsadv "$prog"
  done
  if [ "$vulnerabilities" -gt 0 ]; then
    echo "[!] Advanced CORS scan found vulnerabilities." | tee -a "$RESULTS_DIR/corsadv_scan.txt"
  else
    echo "[+] No advanced CORS vulnerabilities detected." | tee -a "$RESULTS_DIR/corsadv_scan.txt"
  fi
  update_progress corsadv 100
  echo "[-] Advanced CORS Scan completed."
  echo
}

#############################
#    BASIC XSS SCAN
#############################
xss_scan() {
  update_progress xss 0
  echo "[*] Starting Basic XSS Scan..."
  local payload="<script>alert('XSS')</script>"
  local test_url
  if [[ "$target" =~ \? ]]; then
    test_url="${target}${payload}"
  else
    test_url="${target}?q=${payload}"
  fi
  sleep 0.5
  update_progress xss 50
  local response
  response=$(curl -s "$test_url")
  if echo "$response" | grep -q "$payload"; then
    echo "[+] Basic XSS vulnerability detected at: $test_url"
  else
    echo "[-] Basic XSS not detected."
  fi
  update_progress xss 100
  echo "[-] Basic XSS Scan completed."
  echo
}

#############################
#    ADVANCED SCAN (TOOLS)
#############################
advanced_scan() {
  update_progress adv 0
  echo "[*] Starting Advanced Scan..."
  local nmap_target
  nmap_target=$(echo "$target" | sed -e 's#http[s]*://##')
  local nmap_options="-sV -Pn"
  [ "$flag_bypass" -eq 1 ] && { echo "[*] Enabling firewall bypass options..."; nmap_options+=" -f -D RND:10"; }
  echo "[*] Running Nmap scan (options: $nmap_options)..."
  if ! command -v nmap >/dev/null 2>&1; then
    echo "[!] Nmap not found!"
  else
    nmap $nmap_options "$nmap_target" -oN "$RESULTS_DIR/nmap_scan.txt"
    echo "[*] Nmap scan saved to $RESULTS_DIR/nmap_scan.txt."
  fi
  echo "[*] Running Nikto scan on $target..."
  if ! command -v nikto >/dev/null 2>&1; then
    echo "[!] Nikto not found!"
  else
    nikto -h "$target" -output "$RESULTS_DIR/nikto_scan.txt"
    echo "[*] Nikto results saved to $RESULTS_DIR/nikto_scan.txt."
  fi
  echo "[*] Running Gobuster directory scan..."
  if ! command -v gobuster >/dev/null 2>&1; then
    echo "[!] Gobuster not found!"
  else
    local wordlist=""
    if [ -f "$WORDLIST_DIR/dirb/common.txt" ]; then
      wordlist="$WORDLIST_DIR/dirb/common.txt"
    elif [ -f "$WORDLIST_DIR/seclists/Discovery/Web-Content/common.txt" ]; then
      wordlist="$WORDLIST_DIR/seclists/Discovery/Web-Content/common.txt"
    else
      echo "[!] No wordlist found. Skipping Gobuster scan."
    fi
    if [ -n "$wordlist" ]; then
      gobuster dir -u "$target" -w "$wordlist" -o "$RESULTS_DIR/gobuster_scan.txt"
      echo "[*] Gobuster results saved to $RESULTS_DIR/gobuster_scan.txt."
    fi
  fi
  update_progress adv 100
  echo "[-] Advanced Scan completed."
  echo
}

#############################
#     PERSISTENT NUCLEI
#############################
nuclei_scan() {
  update_progress nuclei 0
  echo "[*] Starting Persistent Nuclei Scan..."
  local RESUME_FILE="$RESULTS_DIR/nuclei_resume.txt"
  local OUTPUT_FILE="$RESULTS_DIR/nuclei_scan.txt"
  local TEMPLATE_DIR="${NUCLEI_TEMPLATE_DIR:-/usr/share/nuclei/templates}"
  [ ! -f "$RESUME_FILE" ] && touch "$RESUME_FILE"
  mapfile -t templates < <(find "$TEMPLATE_DIR" -type f -name "*.yaml")
  local total_templates=${#templates[@]}
  echo "[*] Total nuclei templates: $total_templates"
  local current=0
  for tmpl in "${templates[@]}"; do
    if grep -Fxq "$tmpl" "$RESUME_FILE"; then
      echo "Skipping template: $tmpl (already scanned)"
    else
      echo "Scanning with template: $tmpl"
      nuclei -u "$target" -severity "critical,high,medium,low" -t "$tmpl" -silent >> "$OUTPUT_FILE"
      echo "$tmpl" >> "$RESUME_FILE"
    fi
    current=$(( current + 1 ))
    local prog=$(( current * 100 / total_templates ))
    update_progress nuclei "$prog"
  done
  update_progress nuclei 100
  echo "[-] Persistent Nuclei Scan completed. Results in $OUTPUT_FILE."
}

#############################
#     BASIC SHODAN SCAN
#############################
shodan_scan() {
  update_progress shodan 0
  echo "[*] Starting Basic Shodan Scan..."
  if ! command -v shodan >/dev/null 2>&1; then
    echo "[!] Shodan CLI not found! Please install it and set SHODAN_API_KEY."
  else
    shodan host "$target" > "$RESULTS_DIR/shodan_scan.txt"
    echo "[*] Shodan results saved to $RESULTS_DIR/shodan_scan.txt."
  fi
  update_progress shodan 100
  echo
}

#############################
#  ADVANCED SHODAN SCAN
#############################
advanced_shodan_scan() {
  update_progress shodanadv 0
  echo "[*] Starting Advanced Shodan Scan..."
  if [ -z "$SHODAN_API_KEY" ]; then
    echo "[!] SHODAN_API_KEY not set."
  elif ! command -v shodan >/dev/null 2>&1; then
    echo "[!] Shodan CLI not installed!"
  else
    local ip
    ip=$(dig +short "$(echo "$target" | sed -e 's#http[s]*://##' | cut -d'/' -f1)" | head -n1)
    if [ -z "$ip" ]; then
      echo "[!] Could not resolve IP for $target"
    else
      echo "[*] Querying Shodan for IP: $ip..."
      shodan search --fields ip_str,port,org,hostnames,location "$ip" > "$RESULTS_DIR/shodanadv_scan.txt"
      echo "[*] Advanced Shodan results saved to $RESULTS_DIR/shodanadv_scan.txt."
    fi
  fi
  update_progress shodanadv 100
  echo "[-] Advanced Shodan Scan completed."
  echo
}

#############################
#     CVE SCAN
#############################
cve_scan() {
  update_progress cve 0
  echo "[*] Starting CVE Scan..."
  if ! command -v searchsploit >/dev/null 2>&1; then
    echo "[!] searchsploit not found! Please install it."
  else
    searchsploit "$target" > "$RESULTS_DIR/cve_scan.txt"
    echo "[*] CVE results saved to $RESULTS_DIR/cve_scan.txt."
  fi
  update_progress cve 100
  echo
}

#############################
#     BASIC API KEY SCAN
#############################
apikey_scan() {
  update_progress apikey 0
  echo "[*] Starting Basic API Key Scan..."
  local content
  content=$(curl -s "$target")
  local keys
  keys=$(echo "$content" | grep -oE 'api[-_]?key[\"'\'' :=]+[A-Za-z0-9]{32,}')
  if [ -z "$keys" ]; then
    echo "[-] No API keys found."
  else
    echo "[+] API keys discovered:"
    echo "$keys"
  fi
  update_progress apikey 100
  echo "[-] Basic API Key Scan completed."
  echo
}

#############################
#  ADVANCED API KEY SCAN
#############################
advanced_apikey_scan() {
  update_progress apikeyadv 0
  echo "[*] Starting Advanced API Key Scan..."
  local content
  content=$(curl -s "$target")
  local patterns=( 'api[-_]?key[\"'\'' :=]+[A-Za-z0-9]{32,}' '[A-Za-z0-9]{40,}' )
  > "$RESULTS_DIR/apikeyadv_scan.txt"
  local total=${#patterns[@]} count=0 found=0
  for pat in "${patterns[@]}"; do
    local keys
    keys=$(echo "$content" | grep -Eo "$pat")
    if [ -n "$keys" ]; then
      echo "[+] Found API keys (pattern: $pat):" | tee -a "$RESULTS_DIR/apikeyadv_scan.txt"
      echo "$keys" | tee -a "$RESULTS_DIR/apikeyadv_scan.txt"
      found=1
      if [ -n "$API_VALIDATE_URL" ]; then
        for key in $keys; do
          local extracted
          extracted=$(echo "$key" | sed -E 's/.*[=: ]//')
          echo "[*] Validating $extracted..." | tee -a "$RESULTS_DIR/apikeyadv_scan.txt"
          local res
          res=$(curl -s "${API_VALIDATE_URL}?key=${extracted}")
          echo "Validation result: $res" | tee -a "$RESULTS_DIR/apikeyadv_scan.txt"
        done
      fi
    fi
    count=$(( count + 1 ))
    local prog=$(( count * 100 / total ))
    update_progress apikeyadv "$prog"
  done
  [ "$found" -eq 0 ] && echo "[-] No advanced API keys found." >> "$RESULTS_DIR/apikeyadv_scan.txt"
  update_progress apikeyadv 100
  echo "[-] Advanced API Key Scan completed."
  echo
}

#############################
#   CREDENTIAL FILE SCAN
#############################
cred_scan() {
  update_progress cred 0
  echo "[*] Starting Credential File Scan..."
  local homepage
  homepage=$(curl -s "$target")
  local regex='(http[s]?://[^"'\'' >]+\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5))'
  local matches
  matches=$(echo "$homepage" | grep -Eo "$regex" | sort -u)
  local total
  total=$(echo "$matches" | wc -l)
  if [ "$total" -eq 0 ]; then
    echo "[-] No sensitive file URLs found."
  else
    > "$RESULTS_DIR/cred_scan.txt"
    local count=0
    for url in $matches; do
      echo "[*] Checking $url..."
      local code
      code=$(curl -s -o /dev/null -w "%{http_code}" "$url")
      if [ "$code" == "200" ]; then
        echo "[+] Accessible: $url (HTTP $code)" >> "$RESULTS_DIR/cred_scan.txt"
      else
        echo "[-] $url (HTTP $code)" >> "$RESULTS_DIR/cred_scan.txt"
      fi
      count=$(( count + 1 ))
      local prog=$(( count * 100 / total ))
      update_progress cred "$prog"
    done
  fi
  update_progress cred 100
  echo "[-] Credential File Scan completed."
  echo
}

#############################
#    BASIC OPEN REDIRECT SCAN
#############################
open_redirect_scan() {
  update_progress redirect 0
  echo "[*] Starting Basic Open Redirect Scan..."
  local params=("redirect" "url" "next" "return" "data")
  > "$RESULTS_DIR/openredirect_scan.txt"
  local total=${#params[@]} count=0
  for p in "${params[@]}"; do
    local test_url
    if [[ "$target" =~ \? ]]; then
      test_url="${target}&${p}=http://evil.com"
    else
      test_url="${target}?${p}=http://evil.com"
    fi
    local headers
    headers=$(curl -s -I "$test_url")
    if echo "$headers" | grep -qi "Location: http://evil.com"; then
      echo "[+] Vulnerability found using parameter '$p' at: $test_url" >> "$RESULTS_DIR/openredirect_scan.txt"
    else
      echo "[-] Parameter '$p' appears safe." >> "$RESULTS_DIR/openredirect_scan.txt"
    fi
    count=$(( count + 1 ))
    local prog=$(( count * 100 / total ))
    update_progress redirect "$prog"
  done
  update_progress redirect 100
  echo "[-] Basic Open Redirect Scan completed."
  echo
}

#############################
#  ADVANCED OPEN REDIRECT SCAN
#############################
advanced_open_redirect_scan() {
  update_progress redirectadv 0
  echo "[*] Starting Advanced Open Redirect Scan..."
  local params=("redirect" "url" "next" "return" "data" "go" "dest")
  local payloads=("http://evil.com" "https://evil.com" "javascript:alert(1)" "$(urlencode 'http://evil.com')")
  > "$RESULTS_DIR/redirectadv_scan.txt"
  local total=$(( ${#params[@]} * ${#payloads[@]} ))
  local count=0
  for p in "${params[@]}"; do
    for pl in "${payloads[@]}"; do
      local test_url
      if [[ "$target" =~ \? ]]; then
        test_url="${target}&${p}=${pl}"
      else
        test_url="${target}?${p}=${pl}"
      fi
      local headers
      headers=$(curl -s -I "$test_url")
      if echo "$headers" | grep -qi "Location:.*$pl"; then
        echo "[+] Vulnerability found with parameter '$p' and payload '$pl': $test_url" >> "$RESULTS_DIR/redirectadv_scan.txt"
      else
        echo "[-] Parameter '$p' with payload '$pl' appears safe." >> "$RESULTS_DIR/redirectadv_scan.txt"
      fi
      count=$(( count + 1 ))
      local prog=$(( count * 100 / total ))
      update_progress redirectadv "$prog"
    done
  done
  update_progress redirectadv 100
  echo "[-] Advanced Open Redirect Scan completed."
  echo
}

#############################
#    ADVANCED XSS SCAN
#############################
advanced_xss_scan() {
  update_progress xssadv 0
  echo "[*] Starting Advanced XSS Scan..."
  if command -v xsstrike >/dev/null 2>&1; then
    echo "[*] XSStrike detected. Running XSStrike crawl..."
    xsstrike --url "$target" --crawl --digger --timeout 20 -o "$RESULTS_DIR/xsstrike_output.txt"
  else
    echo "[*] XSStrike not found. Running built-in advanced XSS tests..."
    local payloads=(
      "<svg/onload=alert(String.fromCharCode(88,83,83))>"
      "'\"><script>alert(String.fromCharCode(88,83,83))</script>"
      "\"'><img src=x onerror=alert(String.fromCharCode(88,83,83))>"
      "<iframe src=javascript:alert(String.fromCharCode(88,83,83))>"
      "<body onload=alert(String.fromCharCode(88,83,83))>"
      "<sCript>alert(String.fromCharCode(88,83,83))</sCript>"
      "'';!--\"<XSS>=&{()}"
    )
    local params=()
    if [[ "$target" == *"?"* ]]; then
      local param_part
      param_part=$(echo "$target" | cut -d'?' -f2)
      IFS='&' read -ra params <<< "$param_part"
      for i in "${!params[@]}"; do
        params[i]=$(echo "${params[i]}" | cut -d'=' -f1)
      done
    else
      params=("q")
    fi
    local total_tests=$(( ${#payloads[@]} * ${#params[@]} ))
    local count=0
    > "$RESULTS_DIR/advanced_xss_scan.txt"
    for payload in "${payloads[@]}"; do
      local encoded
      encoded=$(urlencode "$payload")
      for p in "${params[@]}"; do
        local test_url
        if [[ "$target" == *"?"* ]]; then
          test_url="${target}&${p}=${encoded}"
        else
          test_url="${target}?${p}=${encoded}"
        fi
        local response
        response=$(curl -s "$test_url")
        if echo "$response" | grep -q "alert(String.fromCharCode(88,83,83))"; then
          echo "[+] Vulnerability detected with payload: $payload on parameter $p at $test_url" >> "$RESULTS_DIR/advanced_xss_scan.txt"
        else
          echo "[-] Payload $payload on parameter $p not reflected." >> "$RESULTS_DIR/advanced_xss_scan.txt"
        fi
        count=$(( count + 1 ))
        local prog=$(( count * 100 / total_tests ))
        update_progress xssadv "$prog"
      done
    done
  fi
  update_progress xssadv 100
  echo "[-] Advanced XSS Scan completed."
  echo
}

#############################
#       USAGE / HELP
#############################
usage() {
  echo "Usage: $0 [OPTIONS] target"
  echo "Basic Options:"
  echo "  --info           Basic Info Disclosure Scan"
  echo "  --sensitive      Basic Sensitive Data Scan"
  echo "  --cors           Basic CORS Scan"
  echo "  --xss            Basic XSS Scan"
  echo "  --adv            Advanced Scan (Nmap, Nikto, Gobuster)"
  echo "  --nuclei         Persistent Nuclei Scan"
  echo "  --shodan         Basic Shodan Scan"
  echo "  --cve            Basic CVE Scan"
  echo "  --apikey         Basic API Key Scan"
  echo "  --cred           Credential File Scan"
  echo "  --openredirect   Basic Open Redirect Scan"
  echo "  --xssadv         Basic Advanced XSS Scan"
  echo "Advanced Options:"
  echo "  --infoadv        Advanced Info Disclosure Scan"
  echo "  --sensadv        Advanced Sensitive Data Scan"
  echo "  --apikeyadv      Advanced API Key Scan"
  echo "  --shodanadv      Advanced Shodan Scan"
  echo "  --redirectadv    Advanced Open Redirect Scan"
  echo "Miscellaneous:"
  echo "  --all            Run all scans"
  echo "  --bypass         Enable firewall bypass options for advanced scans"
  echo "  -h, --help       Display help message"
  echo
  echo "Example:"
  echo "  $0 https://example.com --all --bypass --shodanadv --cve --apikeyadv --cred --redirectadv --xssadv --infoadv --sensadv"
  exit 1
}

#############################
#     ARGUMENT PARSING
#############################
if [ "$#" -lt 2 ]; then
  usage
fi

# Initialize flags.
flag_info=0
flag_infoadv=0
flag_sensitive=0
flag_sensadv=0
flag_cors=0
flag_xss=0
flag_adv=0
flag_nuclei=0
flag_shodan=0
flag_shodanadv=0
flag_cve=0
flag_apikey=0
flag_apikeyadv=0
flag_cred=0
flag_redirect=0
flag_redirectadv=0
flag_xssadv=0
flag_all=0
flag_bypass=0
target=""

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --info)         flag_info=1 ;;
    --infoadv)      flag_infoadv=1 ;;
    --sensitive)    flag_sensitive=1 ;;
    --sensadv)      flag_sensadv=1 ;;
    --cors)         flag_cors=1 ;;
    --xss)          flag_xss=1 ;;
    --adv)          flag_adv=1 ;;
    --nuclei)       flag_nuclei=1 ;;
    --shodan)       flag_shodan=1 ;;
    --shodanadv)    flag_shodanadv=1 ;;
    --cve)          flag_cve=1 ;;
    --apikey)       flag_apikey=1 ;;
    --apikeyadv)    flag_apikeyadv=1 ;;
    --cred)         flag_cred=1 ;;
    --openredirect) flag_redirect=1 ;;
    --redirectadv)  flag_redirectadv=1 ;;
    --xssadv)       flag_xssadv=1 ;;
    --all)          flag_all=1 ;;
    --bypass)       flag_bypass=1 ;;
    -h|--help)      usage ;;
    *)
      if [[ "$1" =~ ^https?:// ]] || [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]]; then
        target="$1"
      else
        echo "Unrecognized parameter: $1"
        usage
      fi
      ;;
  esac
  shift
done

if [ "$flag_all" -eq 1 ]; then
  flag_info=1; flag_infoadv=1; flag_sensitive=1; flag_sensadv=1; flag_cors=1; flag_xss=1;
  flag_adv=1; flag_nuclei=1; flag_shodan=1; flag_shodanadv=1; flag_cve=1;
  flag_apikey=1; flag_apikeyadv=1; flag_cred=1; flag_redirect=1;
  flag_redirectadv=1; flag_xssadv=1;
fi

if [ -z "$target" ]; then
  echo "[!] Error: No target specified."
  usage
fi

#############################
#         MAIN FLOW
#############################
print_banner

# Array to keep track of background process IDs.
pids=()

[ "$flag_info" -eq 1 ]         && { info_disclosure_scan & pids+=($!); }
[ "$flag_infoadv" -eq 1 ]      && { advanced_info_disclosure_scan & pids+=($!); }
[ "$flag_sensitive" -eq 1 ]    && { sensitive_data_scan & pids+=($!); }
[ "$flag_sensadv" -eq 1 ]      && { advanced_sensitive_data_scan & pids+=($!); }
[ "$flag_cors" -eq 1 ]         && { cors_scan & pids+=($!); }
[ "$flag_xss" -eq 1 ]          && { xss_scan & pids+=($!); }
[ "$flag_adv" -eq 1 ]          && { advanced_scan & pids+=($!); }
[ "$flag_nuclei" -eq 1 ]       && { nuclei_scan & pids+=($!); }
[ "$flag_shodan" -eq 1 ]       && { shodan_scan & pids+=($!); }
[ "$flag_shodanadv" -eq 1 ]    && { advanced_shodan_scan & pids+=($!); }
[ "$flag_cve" -eq 1 ]          && { cve_scan & pids+=($!); }
[ "$flag_apikey" -eq 1 ]       && { apikey_scan & pids+=($!); }
[ "$flag_apikeyadv" -eq 1 ]    && { advanced_apikey_scan & pids+=($!); }
[ "$flag_cred" -eq 1 ]         && { cred_scan & pids+=($!); }
[ "$flag_redirect" -eq 1 ]     && { open_redirect_scan & pids+=($!); }
[ "$flag_redirectadv" -eq 1 ]  && { advanced_open_redirect_scan & pids+=($!); }
[ "$flag_xssadv" -eq 1 ]       && { advanced_xss_scan & pids+=($!); }

# Launch the progress monitor.
monitor_progress &
monitor_pid=$!

echo "[*] All scan processes launched. Waiting for completion..."
for pid in "${pids[@]}"; do
  wait "$pid" || echo "[!] Process $pid exited with a non-zero status."
done

if kill -0 "$monitor_pid" 2>/dev/null; then
  wait "$monitor_pid"
fi

echo "[*] All scans completed. Results are stored in the folder: $RESULTS_DIR"
