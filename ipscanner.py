import argparse
import nmap
import socket
import requests
import shodan
import json
import subprocess
import threading
import time

# Replace with your Shodan API key
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"
SCAN_TIMEOUT = 50  # Max time per scan (seconds)


def run_with_timeout(func, *args):
    """Runs a function and prints its output immediately, ensuring it doesn't exceed SCAN_TIMEOUT."""
    result = []

    def target():
        try:
            func(*args)  # Call the function directly to print results
        except Exception as e:
            print(f"[-] Error in {func.__name__}: {e}")

    thread = threading.Thread(target=target)
    thread.start()
    thread.join(timeout=SCAN_TIMEOUT)

    if thread.is_alive():
        print(f"[-] {func.__name__} took too long. Moving to the next scan!")


def ping_scan(ip):
    """Basic ping scan to check if the host is online."""
    print(f"\n[+] Running Ping Scan on {ip}")
    try:
        response = subprocess.run(["ping", "-c", "1", ip], capture_output=True, text=True)
        if response.returncode == 0:
            print(f"[+] {ip} is reachable.\n{response.stdout}")
        else:
            print(f"[-] {ip} is unreachable.")
    except Exception as e:
        print(f"[-] Ping scan failed: {e}")


def nmap_scan(ip):
    """Perform an Nmap scan with multiple modes."""
    print(f"\n[+] Running Nmap Scan on {ip}")
    nm = nmap.PortScanner()
    scan_modes = {
        "TCP Scan": "-sT",
        "UDP Scan": "-sU",
        "OS Detection": "-O",
        "Service Detection": "-sV"
    }

    for scan_name, scan_args in scan_modes.items():
        try:
            print(f"    -> Running: {scan_name} ({scan_args})")
            nm.scan(ip, arguments=scan_args, sudo=True)  # Use sudo for advanced scans
            if ip in nm.all_hosts():
                print(json.dumps(nm[ip], indent=2))
            else:
                print(f"[-] No results for {scan_name}")
        except Exception as e:
            print(f"[-] Nmap error ({scan_name}): {e}")


def shodan_lookup(ip):
    """Perform a Shodan search on an IP address."""
    print(f"\n[+] Running Shodan Lookup on {ip}")
    if not SHODAN_API_KEY:
        print("[-] Missing Shodan API Key! Skipping...")
        return
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        results = api.host(ip)
        print(json.dumps(results, indent=2))
    except shodan.APIError as e:
        print(f"[-] Shodan error: {e}")


def whois_lookup(ip):
    """Perform a Whois lookup."""
    print(f"\n[+] Running Whois Lookup on {ip}")
    try:
        response = requests.get(f"https://rdap.arin.net/registry/ip/{ip}", timeout=SCAN_TIMEOUT)
        print(json.dumps(response.json(), indent=2))
    except Exception as e:
        print(f"[-] Whois lookup failed: {e}")


def reverse_dns(ip):
    """Perform a Reverse DNS lookup."""
    print(f"\n[+] Running Reverse DNS Lookup on {ip}")
    try:
        host = socket.gethostbyaddr(ip)
        print(f"[+] Reverse DNS: {host[0]}")
    except socket.herror:
        print("[-] No PTR record found.")


def geoip_lookup(ip):
    """Perform a GeoIP lookup."""
    print(f"\n[+] Running GeoIP Lookup on {ip}")
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=SCAN_TIMEOUT)
        print(json.dumps(response.json(), indent=2))
    except Exception as e:
        print(f"[-] GeoIP lookup failed: {e}")


def subdomain_enum(domain):
    """Find subdomains using crt.sh."""
    print(f"\n[+] Running Subdomain Enumeration on {domain}")
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        response = requests.get(url, timeout=SCAN_TIMEOUT)
        subdomains = {entry["name_value"] for entry in response.json()}
        print("\n".join(subdomains))
    except Exception as e:
        print(f"[-] Subdomain enumeration failed: {e}")


def main():
    target_ip = input("Enter target IP or domain: ")

    scans = [
        ping_scan,
        nmap_scan,
        shodan_lookup,
        whois_lookup,
        reverse_dns,
        geoip_lookup,
        subdomain_enum
    ]

    for scan in scans:
        run_with_timeout(scan, target_ip)
        print("\n" + "-" * 50)  # Adds a separator for better readability
        time.sleep(2)  # Small delay before next scan


if __name__ == "__main__":
    main()
