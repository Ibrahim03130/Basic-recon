import nmap
from datetime import datetime


def port_scan(target):
    """
    Perform a TCP port scan on a domain or IP.
    Returns a sorted list of open ports with services.
    """

    nm = nmap.PortScanner()
    open_ports = []

    try:
        print("[*] Resolving and scanning target...")
        nm.scan(hosts=target, arguments="-T4 --top-ports 1000")

        hosts = nm.all_hosts()
        if not hosts:
            print("[!] Target not reachable.")
            return open_ports

        scanned_host = hosts[0]  # actual IP scanned

        for protocol in nm[scanned_host].all_protocols():
            if protocol != "tcp":
                continue

            for port, data in nm[scanned_host][protocol].items():
                if data.get("state") == "open":
                    service = data.get("name", "unknown")
                    open_ports.append(f"{port}/tcp ({service})")

    except nmap.PortScannerError:
        print("[!] Nmap is not installed or not accessible.")
    except Exception as e:
        print(f"[!] Scan error: {e}")

    return sorted(open_ports)


def save_results(results, target):
    choice = input("\n[?] Save results to file? (y/n): ").lower()

    if choice == "y":
        filename = input("[?] Enter filename: ").strip()

        with open(filename, "w") as f:
            f.write("Port Scanning Report\n")
            f.write(f"Target: {target}\n")
            f.write(f"Time: {datetime.now()}\n")
            f.write("-" * 40 + "\n")

            if results:
                for port in results:
                    f.write(port + "\n")
            else:
                f.write("No open ports found.\n")

        print(f"[+] Results saved to {filename}")
    else:
        print("[*] Results not saved.")


if __name__ == "__main__":
    target = input("Enter target domain or IP: ").strip()

    print("\n[*] Starting port scan...\n")
    results = port_scan(target)

    if results:
        print("[+] Open ports found:")
        for port in results:
            print(f"    {port}")
    else:
        print("[!] No open ports found.")

    save_results(results, target)
