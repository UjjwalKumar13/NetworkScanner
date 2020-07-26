#! /usr/bin/env python3

import argparse
from scapy.all import *
import scapy.all as scapy

def get_ip():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--targetIP/range",dest="target",help="specify target IP / range")
    options = parser.parse_args()
    return options

def scan(ip):
    arp_req = scapy.ARP(pdst=ip)
    arp_broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    packet = arp_broadcast/arp_req
    answered_list = scapy.srp(packet, timeout=1, verbose=False)[0]
    clients = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc , "mac": element[1].hwsrc}
        clients.append(client_dict)
    return clients

def print_rslt(clients):
    print("\n\t\tSCAN RESULTS :-----\n\n")
    print("IP Address\t\t MAC Address\n")
    print("---------------------------------------------------------------\n")
    for client in clients:
        print(client['ip'] + " \t\t " + client['mac'])

options = get_ip()
scan_rslt = scan(options.target)
print_rslt(scan_rslt)

