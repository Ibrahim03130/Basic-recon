import requests
import argparse
from datetime import datetime
import time

def enumerate_subdomains(domain):
    print(f"""
[*] Subdomain Enumeration Tool
[*] Target: {domain}
[*] Time: {datetime.now()}
{"-" * 50}
""")

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {
        "User-Agent": "Mozilla/5.0 (Subdomain Enumeration Tool)"
    }

    retries = 3

    for attempt in range(1, retries + 1):
        try:
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()

            data = response.json()
            subdomains = set()

            for entry in data:
                name_value = entry.get("name_value")
                if name_value:
                    for sub in name_value.split("\n"):
                        sub = sub.strip().lower()

                        if sub.startswith("*."):
                            sub = sub[2:]

                        if sub.endswith(domain):
                            subdomains.add(sub)

            sorted_subdomains = sorted(subdomains)

            print(f"[+] Total subdomains found: {len(sorted_subdomains)}\n")
            for sub in sorted_subdomains:
                print(sub)

            return sorted_subdomains

        except requests.exceptions.Timeout:
            print(f"[!] Timeout occurred (Attempt {attempt}/{retries})")
            time.sleep(2)

        except Exception as e:
            print(f"[!] Error during subdomain enumeration: {e}")
            return []

    print("[!] Failed to retrieve data after multiple attempts.")
    return []

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Passive Subdomain Enumeration Tool")
    parser.add_argument("-d", "--domain", help="Target domain")

    args = parser.parse_args()
    domain = args.domain if args.domain else input("Enter target domain: ").strip()

    enumerate_subdomains(domain)
