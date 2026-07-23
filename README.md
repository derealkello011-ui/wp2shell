```text
 ██╗  ██╗██████╗ ██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗     
 ██║  ██║██╔══██╗╚════██╗██╔════╝██║  ██║██╔════╝██║     ██║     
 ██║  ██║██████╔╝ █████╔╝███████╗███████║█████╗  ██║     ██║     
 ██║  ██║██╔═══╝ ██╔═══╝ ╚════██║██╔══██║██╔══╝  ██║     ██║     
 ╚█████╔╝██║     ███████╗███████║██║  ██║███████╗███████╗███████╗
  ╚════╝ ╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
            Pre-Authentication RCE Detection Tool
```
An automated, non-destructive vulnerability detection script for the wp2shell pre-authentication Remote Code Execution vulnerability chain in WordPress Core. Designed for security researchers and bug bounty hunters.

## 📌 Vulnerability Overview

wp2shell is a high-severity pre-authentication RCE vulnerability chain affecting WordPress Core. It combines two primary flaws:

    CVE-2026-63030 (Batch REST API Route Desync): An internal array state desync within /wp-json/batch/v1 allows unauthenticated sub-requests to bypass authorization checks and reach internal admin endpoints.

    CVE-2026-60137 (WP_Query SQL Injection): Loose type checking on the author__not_in parameter allows unsanitized strings to be injected directly into raw SQL queries.

Affected Versions

    Vulnerable: WordPress 6.9.0 – 6.9.4 and 7.0.0 – 7.0.1

    Patched: WordPress 6.9.5 and 7.0.2+

🚀 Features

    Passive Version Detection: Checks the target's exposed WordPress version via REST API and meta generator tags.

    REST Endpoint Probe: Verifies if the vulnerable batch processing route (/wp-json/batch/v1) is accessible and active.

    Non-Destructive: Performs safe checks without executing SQL payloads or dropping shell files, making it compliant with Bug Bounty policies (e.g., HackerOne, Bugcrowd).

⚙️ Installation
1. Clone the Repository
Bash

git clone [https://github.com/](https://github.com/)<YOUR-USERNAME>/wp2shell.git
cd wp2shell

2. Install Requirements

This tool requires Python 3.8+ and the requests and packaging modules.
Bash

pip install -r requirements.txt

(Or manually install dependencies: pip install requests packaging)
📖 Usage Format
Bash

python3 wp2shell.py -u <TARGET_URL> [OPTIONS]

Options & Flags
Flag	Long Option	Description	Required
-u	--url	Target WordPress URL (e.g., https://example.com)	Yes
-h	--help	Show help message and exit	No
💡 Usage Example
Basic Vulnerability Check
Bash

python3 wp2shell.py -u http://localhost:8080

Example Output
Plaintext

[*] Scanning target: http://localhost:8080
[+] Detected WordPress Version: 6.9.4
[!] Version 6.9.4 is in the vulnerable range!
[*] Probing /wp-json/batch/v1 REST endpoint...
[+] Batch REST API endpoint is active and accessible.

[VULNERABLE] Target appears highly vulnerable to wp2shell (CVE-2026-63030 / CVE-2026-60137)!

⚠️ Disclaimer

This tool is created for educational purposes, defensive security auditing, and authorized bug bounty research only. Do not test targets without explicit permission or out of scope. The author assumes no liability for unauthorized or misuse of this script.