#!/usr/bin/python3

import nmap
import socket

def banner():
    print("<----------------------->")
    print("Advanced Network Scanner")
    print("<----------------------->\n")

def socket_port_scan(ip, ports):
    print("\n<------ Socket Port Scanner ------>")
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((ip, port))
                if result == 0:
                    print(f"Port {port} is open.")
                else:
                    print(f"Port {port} is closed.")
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
    print("<--------------------------------->\n")

def nmap_scan(ip, scan_type):
    scanner = nmap.PortScanner()
    print("Using Nmap Version: ", scanner.nmap_version())

    if scan_type == 1:  # SYN-ACK Scan
        print("\n<------ SYN-ACK Scan ------>")
        scanner.scan(ip, '1-1024', '-v -sS')
    elif scan_type == 2:  # UDP Scan
        print("\n<------ UDP Scan ------>")
        scanner.scan(ip, '1-1024', '-v -sU')
    elif scan_type == 3:  # Comprehensive Scan
        print("\n<------ Comprehensive Scan ------>")
        scanner.scan(ip, '1-65535', '-v -sS -sV -sC -A -O')
    else:
        print("Invalid scan type selected!")
        return

    print("Scan Info: ", scanner.scaninfo())

    if ip in scanner.all_hosts():
        print(f"\nIP Status: {scanner[ip].state()}")
        print(f"All Protocols: {scanner[ip].all_protocols()}")

        if 'tcp' in scanner[ip].all_protocols():
            print("Open TCP Ports:")
            for port, info in scanner[ip]['tcp'].items():
                print(f"Port {port}: {info['name']} ({info['state']})")
        else:
            print("No open TCP ports found.")

        if 'udp' in scanner[ip].all_protocols():
            print("Open UDP Ports:")
            for port, info in scanner[ip]['udp'].items():
                print(f"Port {port}: {info['name']} ({info['state']})")
        else:
            print("No open UDP ports found.")
    else:
        print(f"The target IP {ip} is not responding or could not be scanned.")
    print("<--------------------------------->\n")

def main():
    banner()
    ip = input("Please Enter IP Address: ").strip()
    
    try:
        socket.gethostbyname(ip)
        print(f"\nResolved IP Address: {ip}\n")
    except socket.gaierror:
        print(f"Invalid IP or hostname: {ip}")
        return

    scan_type = int(input("""
\nPlease Enter the Type of Scan:
1. SYN-ACK Scan
2. UDP Scan
3. Comprehensive Scan
\nYour Choice: """).strip())

    nmap_scan(ip, scan_type)

    ports_to_scan = [22, 80, 443, 8080, 3306, 21, 25]
    socket_port_scan(ip, ports_to_scan)

if __name__ == "__main__":
    main()
