#!/usr/bin/python3

import nmap

scanner = nmap.PortScanner()

print("<----------------------->")
print('Advanced Network Scanner')
print("<----------------------->")

ip_addr = input("Please Enter IP: ")
print(f'IP Address: {ip_addr}')
type(ip_addr)