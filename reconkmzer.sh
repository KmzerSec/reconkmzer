#!/bin/bash
# ReconKmz - Elite Bug Bounty Scanner
# Version: 3.0 - "Black Hat Edition"
# Author: KMZ Security

# -------------------------
# Configuration
# -------------------------
CONFIG_FILE="kmzersec.cfg"
source $CONFIG_FILE 2>/dev/null || { echo -e "[\e[91mERROR\e[0m] Missing config file!"; exit 1; }

# -------------------------
# Global Variables
# -------------------------
declare -A SCAN_STATS=(
    [subdomains]=0
    [urls]=0
    [vulnerabilities]=0
    [critical]=0
    [high]=0
    [secrets]=0
)
TOTAL_STEPS=27
CURRENT_STEP=0
TERM_WIDTH=$(tput cols)

# -------------------------
# ASCII Art & UI Elements
# -------------------------
BANNER=$(cat << "EOF"
\e[38;5;208m
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗███╗   ███╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║  ██║████╗ ████║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║███████║██╔████╔██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══██║██║╚██╔╝██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║  ██║██║ ╚═╝ ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝
\e[0m
EOF
)

PROGRESS_BAR() {
    local width=50
    local filled=$((width * CURRENT_STEP / TOTAL_STEPS))
    local empty=$((width - filled))
    printf "\e[34m[%${filled}s%${empty}s] %3d%%\e[0m" "" "" "$((100 * CURRENT_STEP / TOTAL_STEPS))"
}

SHOW_STATS() {
    printf "\n\e[35m╔══════════════════════════════════════╗\n"
    printf "║ \e[36m%-20s %12s \e[35m║\n" "Subdomains Found:" "${SCAN_STATS[subdomains]}"
    printf "║ \e[36m%-20s %12s \e[35m║\n" "URLs Crawled:" "${SCAN_STATS[urls]}"
    printf "║ \e[36m%-20s %12s \e[35m║\n" "Critical Vulns:" "${SCAN_STATS[critical]}"
    printf "║ \e[36m%-20s %12s \e[35m║\n" "High Severity:" "${SCAN_STATS[high]}"
    printf "║ \e[36m%-20s %12s \e[35m║\n" "Secrets Found:" "${SCAN_STATS[secrets]}"
    printf "╚══════════════════════════════════════╝\e[0m\n"
}

SPINNER() {
    local pid=$!
    local spin='⣾⣽⣻⢿⡿⣟⣯⣷'
    while kill -0 $pid 2>/dev/null; do
        for i in $(seq 0 7); do
            echo -ne "\e[36m${spin:$i:1} ${1}\e[0m \r"
            sleep 0.1
        done
    done
}

# -------------------------
# Core Scanning Functions
# -------------------------
ADVANCED_SUBDOMAIN_ENUM() {
    {
        echo -e "\n\e[33m〄 Phase 1/5: Subdomain Takeover Detection\e[0m"
        subjack -w $TMP_DIR/subdomains_final.txt -t 100 -ssl -c $TOOLS_DIR/fingerprints.json -o $TMP_DIR/takeover.txt &
        
        echo -e "\n\e[33m〄 Phase 2/5: Bruteforce Subdomain Discovery\e[0m"
        puredns bruteforce $WORDLIST_DIR/subdomains/top-1m-110000.txt $1 -r $WORDLIST_DIR/resolvers.txt -q | tee $TMP_DIR/brute.txt &
        
        wait
        cat $TMP_DIR/*.txt | sort -u | httpx -silent -ports 80,443,8080,8443,9443 -status-code -content-length -title -tech-detect -jarm -t 150 -o $TMP_DIR/subdomains_rich.json
        
        SCAN_STATS[subdomains]=$(jq length $TMP_DIR/subdomains_rich.json)
        ((CURRENT_STEP+=2))
    } > /dev/null 2>&1 &
    SPINNER "Subdomain Enumeration"
}

ELITE_URL_DISCOVERY() {
    {
        echo -e "\n\e[33m〄 Phase 3/5: Advanced URL Harvesting\e[0m"
        gospider -S $TMP_DIR/subdomains_final.txt -t 5 -c 500 -d 3 --other-source --include-subs --subs --json -o $TMP_DIR/gospider_out &
        
        echo -e "\n\e[33m〄 Phase 4/5: JavaScript Analysis Matrix\e[0m"
        jsu -i $TMP_DIR/js_urls.txt -o $TMP_DIR/js_analysis -c -d -f &
        
        wait
        cat $TMP_DIR/gospider_out/*.json | jq -r '.output' | sort -u > $TMP_DIR/urls.txt
        SCAN_STATS[urls]=$(wc -l < $TMP_DIR/urls.txt)
        ((CURRENT_STEP+=2))
    } > /dev/null 2>&1 &
    SPINNER "URL Discovery"
}

AI_VULNERABILITY_SCAN() {
    {
        echo -e "\n\e[33m〄 Phase 5/5: Neural Vulnerability Assessment\e[0m"
        
        # AI-Powered Analysis
        python3 $TOOLS_DIR/ai_scanner.py -i $TMP_DIR/urls.txt -o $TMP_DIR/ai_findings.json &
        
        # Quantum Nuclei Scan
        nuclei -l $TMP_DIR/subdomains_resolved.txt -t ~/nuclei-templates/ -severity critical,high -es info,unknown -stats -j -o $TMP_DIR/nuclei_results.json -hm -rl 150 -c 150 -irt 3s -nm
        
        # Dark XSS Scanner
        dalfox file $TMP_DIR/urls.txt --deep-domxss --multicast --blind $XSS_SERVER --worker 100 --mining-dict $WORDLIST_DIR/xss-payloads.txt -o $TMP_DIR/xss_results.txt &
        
        wait
        
        # Process findings
        SCAN_STATS[critical]=$(jq 'select(.severity == "critical")' $TMP_DIR/nuclei_results.json | jq -s length)
        SCAN_STATS[high]=$(jq 'select(.severity == "high")' $TMP_DIR/nuclei_results.json | jq -s length)
        ((CURRENT_STEP+=3))
    } > /dev/null 2>&1 &
    SPINNER "Vulnerability Scanning"
}

# -------------------------
# Reporting & Output
# -------------------------
GENERATE_ELITE_REPORT() {
    {
        echo -e "\n\e[33m〄 Generating Executive Report\e[0m"
        
        # Convert to HTML with AI analysis
        python3 $TOOLS_DIR/report_gen.py \
            --nuclei $TMP_DIR/nuclei_results.json \
            --subdomains $TMP_DIR/subdomains_rich.json \
            --ai $TMP_DIR/ai_findings.json \
            --output $REPORTS_DIR/full_report.html
        
        # Generate vulnerability distribution chart
        python3 $TOOLS_DIR/chart_gen.py $REPORTS_DIR/full_report.html
        
        # Open report in browser
        xdg-open $REPORTS_DIR/full_report.html 2>/dev/null
    } > /dev/null 2>&1 &
    SPINNER "Report Generation"
}

# -------------------------
# Main Execution
# -------------------------
main() {
    clear
    echo -e "$BANNER"
    trap "echo -e '\n\e[31m✘ Scan interrupted! Use same command to resume.\e[0m'; exit 1" SIGINT
    
    while true; do
        clear
        echo -e "$BANNER"
        SHOW_STATS
        PROGRESS_BAR
        sleep 1
    done &
    
    init_directories
    ADVANCED_SUBDOMAIN_ENUM $1
    ELITE_URL_DISCOVERY
    AI_VULNERABILITY_SCAN
    GENERATE_ELITE_REPORT
    
    wait
    echo -e "\n\e[32m✓ Elite Scan Complete! View report: $REPORTS_DIR/full_report.html\e[0m"
    kill $! 2>/dev/null
    exit 0
}

main "$@"
