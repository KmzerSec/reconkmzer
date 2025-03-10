# ReconKmzer

**ReconKmzer** is an advanced, automated reconnaissance and vulnerability scanning tool designed for bug bounty hunters and security researchers. It orchestrates a chain of powerful open-source tools to scan target domains for sensitive data exposures, repository leaks, misconfigurations, and a variety of web vulnerabilities.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Scanning Flow](#scanning-flow)
- [Next Steps and Enhancements](#next-steps-and-enhancements)
- [License](#license)

---

## Overview

ReconKmzer automates the process of gathering vital reconnaissance data from target domains through a series of sequential steps. It employs multiple tools to fingerprint targets, enumerate subdomains, fuzz directories, test for vulnerabilities (e.g., SQL injections, XSS, path traversal, etc.), discover exposed secrets, perform visual recon, and finally, run severity-filtered scans using nuclei for vulnerability verification.

The tool also offers:
- **Resume functionality:** In the event of an interruption (e.g., a laptop shutdown), ReconKmzer will continue from where it left off.
- **Dynamic Progress Indicators:** See percentage completion and elapsed time for each scan step.
- **HTML Reporting:** Consolidated, detailed HTML reports are generated for each target.
- **Wordlist Generation:** Custom “power wordlists” for tools like Gobuster and Nmap.
- **Automatic Installation & Updates:** With the `--install` flag, the tool will verify and install all required tools (with special handling for tools such as XSStrike via pipx).
- **Extensibility:** Easily add new scanning phases or integrate custom tools such as Aquatone for screenshots, massdns for fast DNS recon, AI vulnerability scanners, and more.

---

## Features

- **Chained Scanning Phases:**  
  1. **whatweb:** Fingerprinting  
  2. **Recon & Enumeration:** (Assetfinder, Knockpy, CTFR/subdomain takeover)  
  3. **Directory Fuzzing:** (ffuf, wfuzz, dirsearch with dynamic wordlists)  
  4. **Vulnerability Testing:** (SQLMap, Dalfox, XSStrike, Testssl.sh)  
  5. **API/Secrets Discovery:** (TruffleHog, SecretFinder, gitleaks, Shodan advanced scan)  
  6. **Visual Recon:** (Aquatone, Eyewitness, AutoRecon)  
  7. **Severity-based Nuclei Scanning:** (Filtering vulnerabilities by critical, high, etc.)

- **Resume Functionality:** Restarts where it left off using a resume log.
- **Dynamic Progress Display:** Shows percentage progress and elapsed time per tool.
- **HTML Report Generation:** Consolidates output logs into a beautiful, detailed report.
- **Power Wordlist Generation:** Merges or creates wordlists optimized for directory brute-forcing and port scanning.
- **Automatic Tool Verification/Installation:**  
  - Uses pipx to install XSStrike.  
  - Optionally installs missing tools via `--install`.
- **Extensible and Modular:** Easily integrate additional tools and scan phases.

---

## Requirements

- A **Bash** shell (Linux, macOS, or WSL on Windows).
- **apt-get** (or another package manager in case you adapt the install routines).
- Python3 with **pipx** installed (for XSStrike installation).
- Required external tools (detailed below):
  - whatweb
  - assetfinder
  - knockpy
  - ffuf, wfuzz, dirsearch
  - sqlmap, dalfox, xsstrike, testssl.sh
  - trufflehog
  - aquatone (see [Aquatone Installation](#aquatone-installation-on-kali-linux))
  - eyewitness, autorecon
  - nuclei

---

## Installation

1. **Clone or download this repository.**

2. **Set executable permissions:**

   ```bash
   chmod +x reconkmz.sh
./reconkmz.sh --install
Note: XSStrike will be installed using pipx. Ensure pipx is installed by running:

bash
pip install pipx
Aquatone Installation on Kali Linux:

Download: Visit Aquatone Releases and download the latest release.

Unzip:

bash
unzip aquatone_linux_amd64_1.7.0.zip
Move Binary:

bash
sudo mv aquatone /usr/bin/
Configuration
Edit the configuration section (or create a file named kmzersec.cfg) to specify:

bash
# Configuration example in kmzersec.cfg:
TOOLS_DIR="$HOME/tools"
WORDLIST_DIR="$HOME/wordlists"
REPORTS_DIR="$(pwd)/reports"
TMP_DIR="$(pwd)/tmp"

# API Keys (uncomment and set):
#SHODAN_API_KEY="YOUR_SHODAN_API_KEY"
#WHOISXML_API="YOUR_WHOISXML_API_KEY"
#XSS_SERVER="YOUR_XSS_SERVER_KEY"
Ensure that your API keys are properly set before running scans that require external integrations (e.g., Shodan).

Usage
ReconKmzer supports several options:

Scan a Single Domain:

bash
./reconkmz.sh -d example.com
Scan Multiple Domains (one domain per line):

bash
./reconkmz.sh -dl domains.txt
Generate Power Wordlists for Gobuster/Nmap:

bash
./reconkmz.sh -w
Update Tools (e.g., nuclei templates):

bash
./reconkmz.sh --update
Generate Python Payload Tester (for XSS, SQLi, etc.):

bash
./reconkmz.sh --payload-tester
Install Required Tools (if not already installed):

bash
./reconkmz.sh --install
Scanning Flow
The scanning process is designed to run sequentially as follows:

+----------------+
|    whatweb     |  <-- Fingerprints target
+----------------+
         |
         v
+-----------------------------+
| Recon & Enumeration         |
| (Assetfinder, Knockpy, CTFR)|
+-----------------------------+
         |
         v
+-----------------------------+
| Directory Fuzzing           |
| (ffuf, wfuzz, dirsearch)    |
+-----------------------------+
         |
         v
+-----------------------------+
| Vulnerability Testing       |
| (SQLMap, Dalfox, XSStrike,   |
|  Testssl.sh)                |
+-----------------------------+
         |
         v
+-----------------------------+
| API/Secrets Discovery       |
| (TruffleHog, Shodan, etc.)  |
+-----------------------------+
         |
         v
+-----------------------------+
| Visual Recon                |
| (Aquatone, Eyewitness,      |
|  AutoRecon)                 |
+-----------------------------+
         |
         v
+-----------------------------+
| Nuclei Scanning             |
| (Severity-based: critical,  |
|  high, medium, low, info)   |
+-----------------------------+

As each phase runs, progress, percentage completed, and elapsed time are displayed. All results are stored in individual target folders (within the Reports directory) and later aggregated into an HTML report.

Next Steps and Enhancements
Integrate Additional Tools: Enhance recon by adding tools such as massdns for rapid DNS discovery, specialized server-side XSS and blind XSS scanners, and AI-powered vulnerability scanners.

Adjust Parameters: Customize command-line parameters of each tool to optimize scanning based on your target’s profile or to bypass firewall restrictions.

Advanced Wordlist Generation: Combine multiple wordlist sources or employ techniques to generate even more creative wordlists.

Notifications: Integrate email or Slack notifications for when scans complete.

Automated Updates: Expand the update routine to cover further tools and dependencies.

Extended HTML Reporting: Provide charts, timelines, and detailed vulnerability information for easier bug bounty reporting.

API-Key Validations: Create utilities to validate your API keys (e.g., Shodan) and ensure the integrations operate smoothly.

License
Optional: Include your open source license information here. For example, you might choose the MIT License, Apache License 2.0, etc.

Contact
For improvements, bug reports, or feature requests, please open an issue or contact the maintainer.
