import whois
import argparse
from datetime import datetime

def whois_lookup(domain):
    print(f"""
[*] WHOIS Lookup Tool
[*] Target: {domain}
[*] Time: {datetime.now()}
{"-" * 50}
""")

    try:
        w = whois.whois(domain)

        print(f"[+] Registrar      : {w.registrar}")

        # Creation Date
        if isinstance(w.creation_date, list):
            print(f"[+] Creation Date  : {w.creation_date[0]}")
        else:
            print(f"[+] Creation Date  : {w.creation_date}")

        # Expiry Date
        if isinstance(w.expiration_date, list):
            print(f"[+] Expiry Date    : {w.expiration_date[0]}")
        else:
            print(f"[+] Expiry Date    : {w.expiration_date}")

        print("[+] Name Servers   :")
        if w.name_servers:
            for ns in w.name_servers:
                print(f"    {ns}")
        else:
            print("    [!] No name servers found")

    except Exception as e:
        print(f"[!] WHOIS lookup failed: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Basic WHOIS Lookup Tool")
    parser.add_argument("-d", "--domain", help="Target domain")

    args = parser.parse_args()

    if args.domain:
        domain = args.domain
    else:
        domain = input("Enter target domain: ").strip()

    whois_lookup(domain)
