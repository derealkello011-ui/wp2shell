#!/usr/bin/env python3
import requests
import re
import argparse
from packaging import version

# Disable TLS warnings for testing
requests.packages.urllib3.disable_warnings()

def check_wp_version(target_url):
    """
    Passively checks the target WordPress version via REST API or meta tags.
    """
    version_url = f"{target_url.rstrip('/')}/wp-json/"
    headers = {'User-Agent': 'Mozilla/5.0 (Security Scanner)'}
    
    try:
        res = requests.get(version_url, headers=headers, timeout=10, verify=False)
        if res.status_code == 200:
            # Check version header or body generator
            site_info = res.json()
            # Some REST endpoints disclose the generator/version
            wp_version = site_info.get('namespaces', [])
            
        # Fallback to main page parsing
        main_res = requests.get(target_url, headers=headers, timeout=10, verify=False)
        match = re.search(r'name="generator" content="WordPress ([0-9.]+)"', main_res.text)
        if match:
            return match.group(1)
            
    except Exception as e:
        print(f"[-] Error fetching version: {e}")
    return None

def check_batch_endpoint(target_url):
    """
    Checks if the REST batch endpoint is active and exposed.
    """
    endpoint = f"{target_url.rstrip('/')}/wp-json/batch/v1"
    headers = {'Content-Type': 'application/json'}
    
    # Send an empty or basic batch JSON payload
    payload = {"requests": []}
    
    try:
        res = requests.post(endpoint, json=payload, headers=headers, timeout=10, verify=False)
        # 200 OK or 400 Bad Request indicates the route exists and processes batch JSON
        if res.status_code in [200, 400]:
            return True
    except Exception as e:
        print(f"[-] Error probing batch endpoint: {e}")
    return False

def is_vulnerable_version(ver_str):
    """
    Checks if version falls into vulnerable ranges:
    6.9.0 <= ver <= 6.9.4 OR 7.0.0 <= ver <= 7.0.1
    """
    try:
        v = version.parse(ver_str)
        v_690, v_694 = version.parse("6.9.0"), version.parse("6.9.4")
        v_700, v_701 = version.parse("7.0.0"), version.parse("7.0.1")
        
        if (v_690 <= v <= v_694) or (v_700 <= v <= v_701):
            return True
    except Exception:
        pass
    return False

def main():
    parser = argparse.ArgumentParser(description="wp2shell Safe Vulnerability Checker")
    parser.add_argument("-u", "--url", required=True, help="Target WordPress URL (e.g. http://example.com)")
    args = parser.parse_args()

    target = args.url
    print(f"[*] Scanning target: {target}")
    
    wp_ver = check_wp_version(target)
    if wp_ver:
        print(f"[+] Detected WordPress Version: {wp_ver}")
        if is_vulnerable_version(wp_ver):
            print(f"[!] Version {wp_ver} is in the vulnerable range!")
        else:
            print(f"[-] Version {wp_ver} is patched or outside the affected branch.")
    else:
        print("[-] Could not reliably detect WordPress version automatically.")

    print("[*] Probing /wp-json/batch/v1 REST endpoint...")
    if check_batch_endpoint(target):
        print("[+] Batch REST API endpoint is active and accessible.")
    else:
        print("[-] Batch REST API endpoint is unreachable or disabled.")

    if wp_ver and is_vulnerable_version(wp_ver) and check_batch_endpoint(target):
        print("\n[VULNERABLE] Target appears highly vulnerable to wp2shell (CVE-2026-63030 / CVE-2026-60137)!")
    else:
        print("\n[SAFE] Target does not meet conditions for wp2shell exploitation.")

if __name__ == "__main__":
    main()