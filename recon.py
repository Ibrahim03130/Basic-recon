import argparse
import socket
from datetime import datetime
import dns.resolver
import requests
import whois as pywhois

# ---------------- GLOBAL OUTPUT ----------------
OUTPUT = []

def log(msg):
    print(msg)
    OUTPUT.append(msg)

# ---------------- WHOIS ----------------
def whois_lookup(domain):
    log("\n[*] WHOIS Lookup")
    try:
        data = pywhois.whois(domain)
        log(f"Registrar      : {data.registrar}")
        log(f"Creation Date  : {data.creation_date}")
        log(f"Expiry Date    : {data.expiration_date}")
        log("Name Servers:")
        for ns in data.name_servers or []:
            log(f"  {ns}")
    except Exception as e:
        log(f"[!] WHOIS error: {e}")

# ---------------- DNS ENUM ----------------
def dns_enum(domain):
    log("\n[*] DNS Enumeration")
    resolver = dns.resolver.Resolver()
    for record in ["A", "AAAA", "MX", "NS", "TXT"]:
        try:
            answers = resolver.resolve(domain, record)
            log(f"{record} Records:")
            for r in answers:
                log(f"  {r.to_text()}")
        except Exception:
            pass

# ---------------- SUBDOMAIN ENUM ----------------
def subdomain_enum(domain):
    log("\n[*] Subdomain Enumeration (crt.sh)")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    try:
        r = requests.get(
            url,
            timeout=30,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        r.raise_for_status()

        subs = set()
        for entry in r.json():
            for name in entry.get("name_value", "").split("\n"):
                name = name.replace("*.", "").strip().lower()
                if name.endswith(domain):
                    subs.add(name)

        if subs:
            for sub in sorted(subs):
                log(f"  {sub}")
        else:
            log("  No subdomains found")

    except requests.exceptions.Timeout:
        log("[!] crt.sh timed out — try again later or use VPN")
    except Exception as e:
        log(f"[!] Subdomain error: {e}")


# ---------------- PORT SCAN ----------------
def port_scan(target):
    log("\n[*] Port Scan")
    try:
        import nmap
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments="-T4 --top-ports 500")
        host = nm.all_hosts()[0]
        for proto in nm[host].all_protocols():
            if proto == "tcp":
                for port, data in nm[host][proto].items():
                    if data["state"] == "open":
                        log(f"{port}/tcp ({data['name']})")
    except Exception as e:
        log(f"[!] Port scan error: {e}")

# ---------------- BANNER GRAB ----------------
def banner_grab(target, ports=[80, 443]):
    log("\n[*] Banner Grabbing")
    for port in ports:
        try:
            with socket.socket() as s:
                s.settimeout(3)
                s.connect((target, port))
                s.send(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                banner = s.recv(1024).decode(errors="ignore").strip()
                log(f"{port}: {banner}")
        except Exception:
            pass

# ---------------- SAVE FILE ----------------
def save_to_file():
    choice = input("\n[?] Save results to file? (y/n): ").lower()
    if choice == "y":
        filename = input("[?] Enter filename: ").strip()
        with open(filename, "w") as f:
            for line in OUTPUT:
                f.write(line + "\n")
        print(f"[+] Results saved to {filename}")

# ---------------- MAIN ----------------
parser = argparse.ArgumentParser(description="Unified Recon Tool")
parser.add_argument("-t", "--target", help="Target domain or IP")
parser.add_argument("--whois", action="store_true")
parser.add_argument("--dns", action="store_true")
parser.add_argument("--subs", action="store_true")
parser.add_argument("--ports", action="store_true")
parser.add_argument("--banner", action="store_true")

args = parser.parse_args()
target = args.target or input("Enter target domain or IP: ").strip()

log("\n[*] Unified Recon Tool Started")
log(f"[*] Target: {target}")
log(f"[*] Time: {datetime.now()}")
log("-" * 50)

if not any([args.whois, args.dns, args.subs, args.ports, args.banner]):
    whois_lookup(target)
    dns_enum(target)
    subdomain_enum(target)
    port_scan(target)
    banner_grab(target)
else:
    if args.whois: whois_lookup(target)
    if args.dns: dns_enum(target)
    if args.subs: subdomain_enum(target)
    if args.ports: port_scan(target)
    if args.banner: banner_grab(target)

log("\n[*] Recon Completed")
save_to_file()
