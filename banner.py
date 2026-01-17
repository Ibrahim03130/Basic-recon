import socket
import argparse
from datetime import datetime

def grab_banner(ip, port, timeout=3):
    output = []

    header = f"""
[*] Banner Grabbing Tool
[*] Target: {ip}:{port}
[*] Time: {datetime.now()}
{"-" * 50}
"""
    print(header)
    output.append(header)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            print(f"[*] Connecting to {ip}:{port}...")
            s.connect((ip, port))

            # Try HTTP trigger (harmless for non-HTTP services)
            try:
                request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
                s.sendall(request.encode())
            except Exception:
                pass

            try:
                banner = s.recv(2048)
                if banner:
                    decoded = banner.decode(errors="ignore").strip()
                    print("[+] Banner received:")
                    print(decoded)
                    output.append("[+] Banner received:")
                    output.append(decoded)
                else:
                    msg = "[!] No banner received."
                    print(msg)
                    output.append(msg)

            except socket.timeout:
                msg = "[!] Service did not send a banner."
                print(msg)
                output.append(msg)

    except socket.timeout:
        msg = "[!] Connection timed out."
        print(msg)
        output.append(msg)
    except ConnectionRefusedError:
        msg = "[!] Connection refused (port closed)."
        print(msg)
        output.append(msg)
    except Exception as e:
        msg = f"[!] Error: {e}"
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

def main():
    parser = argparse.ArgumentParser(description="Simple Banner Grabbing Tool")
    parser.add_argument("-i", "--ip", help="Target IP address")
    parser.add_argument("-p", "--port", type=int, help="Target port")
    parser.add_argument("-o", "--output", help="Save output to file")

    args = parser.parse_args()

    # Ask for IP if not provided
    if not args.ip:
        args.ip = input("Enter Target IP: ").strip()

    # Ask for port if not provided
    if not args.port:
        args.port = int(input("Enter Target Port: ").strip())

    results = grab_banner(args.ip, args.port)

    # Save automatically if -o is used
    if args.output:
        with open(args.output, "w") as f:
            for line in results:
                f.write(line + "\n")
        print(f"\n[+] Results saved to {args.output}")
    else:
        save_results(results)

if __name__ == "__main__":
    main()
