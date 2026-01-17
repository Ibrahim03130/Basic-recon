import dns.resolver
import dns.reversename
import argparse
from datetime import datetime

def enumerate_dns(domain):
    output = []

    banner = f"""
[*] DNS Enumeration Tool
[*] Target: {domain}
[*] Time: {datetime.now()}
{"-" * 50}
"""
    print(banner)
    output.append(banner)

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 6

    record_types = ['A', 'AAAA', 'MX', 'NS', 'SOA', 'CNAME', 'TXT']
    ip_addresses = []  # store IPs for reverse lookup

    for record in record_types:
        header = f"\n[+] {record} Records:"
        print(header)
        output.append(header)

        try:
            answers = resolver.resolve(domain, record)
            for answer in answers:
                result = f"    {answer.to_text()}"
                print(result)
                output.append(result)

                # Save IPs for reverse lookup
                if record in ['A', 'AAAA']:
                    ip_addresses.append(answer.to_text())

        except dns.resolver.NoAnswer:
            msg = f"    [!] No {record} record found."
            print(msg)
            output.append(msg)

        except dns.resolver.NXDOMAIN:
            msg = f"    [!] Domain '{domain}' does not exist."
            print(msg)
            output.append(msg)
            return output

        except dns.resolver.Timeout:
            msg = "    [!] Request timed out."
            print(msg)
            output.append(msg)

        except Exception as e:
            msg = f"    [!] Error: {e}"
            print(msg)
            output.append(msg)

    # Reverse DNS Lookup (PTR)
    if ip_addresses:
        header = "\n[+] Reverse DNS Lookup (PTR Records):"
        print(header)
        output.append(header)

        for ip in ip_addresses:
            try:
                reverse_name = dns.reversename.from_address(ip)
                answers = resolver.resolve(reverse_name, "PTR")
                for answer in answers:
                    result = f"    {ip} -> {answer.to_text()}"
                    print(result)
                    output.append(result)

            except dns.resolver.NoAnswer:
                msg = f"    [!] No PTR record found for {ip}"
                print(msg)
                output.append(msg)

            except Exception as e:
                msg = f"    [!] Reverse lookup error for {ip}: {e}"
                print(msg)
                output.append(msg)

    return output

def save_results(data):
    choice = input("\n[?] Do you want to save the results to a file? (y/n): ").lower()
    if choice == "y":
        filename = input("[?] Enter output filename: ").strip()
        with open(filename, "w") as f:
            for line in data:
                f.write(line + "\n")
        print(f"[+] Results saved to {filename}")
    else:
        print("[*] Results not saved.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Basic DNS Enumeration Tool")
    parser.add_argument("-d", "--domain", help="Target domain")
    parser.add_argument("-o", "--output", help="Save output to file (optional)")

    args = parser.parse_args()

    if args.domain:
        target_domain = args.domain
    else:
        target_domain = input("Enter target domain: ").strip()

    results = enumerate_dns(target_domain)

    if args.output:
        with open(args.output, "w") as f:
            for line in results:
                f.write(line + "\n")
        print(f"\n[+] Results saved to {args.output}")
    else:
        save_results(results)
