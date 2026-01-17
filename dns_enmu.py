import dns.resolver
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

        except dns.resolver.NoAnswer:
            msg = f"    [!] No {record} record found."
            print(msg)
            output.append(msg)

        except dns.resolver.NXDOMAIN:
            msg = f"    [!] Domain '{domain}' does not exist."
            print(msg)
            output.append(msg)
            break

        except dns.resolver.Timeout:
            msg = "    [!] Request timed out."
            print(msg)
            output.append(msg)

        except Exception as e:
            msg = f"    [!] Error: {e}"
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

    # Domain selection
    if args.domain:
        target_domain = args.domain
    else:
        target_domain = input("Enter target domain: ").strip()

    results = enumerate_dns(target_domain)

    # Output selection
    if args.output:
        with open(args.output, "w") as f:
            for line in results:
                f.write(line + "\n")
        print(f"\n[+] Results saved to {args.output}")
    else:
        save_results(results)

