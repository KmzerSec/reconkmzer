# reconkmzer
ReconKmzer  automates the entire process of reconnaissance for you. It outperforms the work of subdomain enumeration along with various vulnerability checks and obtaining maximum information about your target.
# kmzersec - Automated Recon & Vulnerability Scanner

**kmzersec** is an advanced Bash-based tool designed for automated recon and vulnerability scanning. It integrates a wide array of popular tools to help penetration testers, bug bounty hunters, and security researchers discover common vulnerabilities—such as information disclosure (passwords, API keys, credentials, tokens), path traversal, IDOR, CORS misconfigurations, open redirect, CVE vulnerabilities, XSS, SQLi, and subdomain takeover—on target domains.

> **Disclaimer:**  
> Use this tool **ONLY** on websites and networks that you are explicitly authorized to test. Unauthorized usage is illegal and unethical.

---

## Features

- **Comprehensive Scanning:**  
  - **WhatWeb:** Runs first to perform fingerprinting of the target.
  - **Subdomain Enumeration:** Uses `subfinder` and `amass` for extensive subdomain discovery.
  - **Directory Brute-Force:** Uses `Gobuster` with a “power wordlist” (auto-generated if no wordlist is provided) for directory and file enumeration.
  - **Port Scanning:** Uses `Nmap` with `-Pn` to bypass firewalls.
  - **Vulnerability Assessments:**  
    - **SQLMap:** Scans for SQL injection vulnerabilities in high-risk mode.  
    - **Nuclei:** Checks for vulnerabilities with severities from critical to informational.
- **Resilient Execution:**  
  - Checkpoint markers allow the script to resume where it left off if interrupted or upon system shutdown.
- **Reporting:**  
  - Generates an aggregated HTML report that consolidates all findings.
  - Creates an advanced Python payload tester (`advanced_payload_tester.py`) for parameter-based testing (XSS, SQLi, etc.).
- **Extensible:**  
  - Easily add more tools (e.g., Aquatone, massdns, Nikto) and integrate additional features like notifications (Slack, email) or automated updates.
- **Configuration:**  
  - All configuration files and scan outputs are stored in a base folder called `reconkmzer`.

---

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/USERNAME/REPOSITORY_NAME.git
   cd REPOSITORY_NAME
2. Setup Configurations:

Create or modify the configuration file kmzersec.cfg in the base folder (reconkmzer).

Example contents for kmzersec.cfg:

bash
TOOLS_DIR="$HOME/tools"
WORDLIST_DIR="reconkmzer/wordlists"
REPORTS_DIR="reconkmzer/reports"
TMP_DIR="reconkmzer/tmp"

3. Setup API Keys:

Create an api_keys.txt file in the base folder (reconkmzer).

Example contents:

shodan=YOUR_SHODAN_API_KEY
censys=YOUR_CENSYS_API_KEY

This file is used by the script to integrate external intelligence APIs.

4. Install Required Tools:

Ensure that the following tools are installed and available in your system PATH:

whatweb

gobuster

nmap

sqlmap

nuclei

amass

subfinder

curl

python3

Installation methods will vary by tool (using packages, apt, or cloning Git repositories).

5. Make the Script Executable:

bash
chmod +x kmzersec.sh
Usage
The script supports several options to customize your scans:

-d: Specify a single domain.

-dl: Provide a file containing a list of domains (one per line).

-w: Supply a custom wordlist for directory scanning. If omitted, a power wordlist is auto-generated.

-o: Override the default output directory for reports.

Examples
Scan a Single Domain:

bash
./kmzersec.sh -d example.com -w my_wordlist.txt
Scan Multiple Domains (using a file):

bash
./kmzersec.sh -dl domains.txt -w my_wordlist.txt
After the scan completes, view the consolidated HTML report in the designated reports folder.

How It Works
Initialization: Displays an attractive ASCII banner and loads configuration settings and API keys.

Scanning Process:

WhatWeb runs first to fingerprint the target.

The script then sequentially performs subdomain enumeration, directory brute-forcing, port scans, vulnerability assessments (SQLMap, Nuclei), and more.

Checkpoint markers allow the script to resume from where it stopped in case of interruption.

Reporting:

Each scanning phase creates its own detailed output file.

All results are aggregated into a single HTML report and complemented by an advanced Python payload tester.

Extending kmzersec
Future enhancements you might consider include:

Additional Tools: Incorporate Aquatone for screenshots, massdns for fast DNS recon, Nikto for web server vulnerability scanning, and advanced Shodan API integrations.

Notifications: Integrate email or Slack notifications upon scan completion.

Auto-Installation: Create scripts to auto-install missing dependencies.

Parallel Processing: Improve performance by parallelizing scans.

Customized Wordlists: Develop algorithms to generate context-aware wordlists dynamically.

Contributing
Contributions are welcome! Please open an issue or submit a pull request with improvements, bug fixes, or new feature ideas. Make sure to follow best practices and document your changes.

License
This project is provided for educational and authorized penetration testing purposes only. Please refer to the LICENSE file for more details.

Happy Reconning! Stay ethical and responsible.
