# Netdiscover is used to scan the networks. Its python package netdiscover
# import scapy library :=> pip install scapy
# !/usr/bin/env python


import sys
import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP/IP Range")
    options = parser.parse_args()
    return options


def scan(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_packets = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
    print(answered_packets)
    clients_list = []
    for element in answered_packets:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)

    return clients_list


def print_result(results_list):
    print("\tIP\t\t MAC Address")
    print("-------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)
