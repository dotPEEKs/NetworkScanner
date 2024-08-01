#!/usr/bin/env python3

# -*- encoding: utf-8 -*-

import os
import sys
import json
import ipaddress
from scapy.all import srp
from scapy.all import ARP
from scapy.all import Ether
from argparse import ArgumentParser

oui_vendor_list = json.loads(open("out.json","r").read())

def check_ip_validation(ip_addr: str) -> bool:
    try:
        ipaddress.ip_network(ip_addr)
    except Exception as e:
        return False
    return True
def get_oui_vendor(source: dict,mac_addr: str) -> str:
    base_mac = mac_addr[:8].upper()
    return "Unknown vendor" if source.get(base_mac) is None else source.get(base_mac)
def scan_network(ip_addr: str):
    if not check_ip_validation(ip_addr):
        print("Invalid ip range: %s " % (ip_addr))
        return
    broadcast_packet = Ether(dst = "FF:FF:FF:FF:FF:FF") / ARP(pdst = ip_addr)
    (answered_packets,_) = srp(broadcast_packet,timeout = 2,verbose = False) # for show not showing status while sending packets

    for packets in answered_packets[1]:
        indent = " " * (20 - len(packets.psrc))
        print(f"IP: {packets.psrc} {indent} MAC: {packets.hwsrc}({get_oui_vendor(oui_vendor_list,packets.hwsrc)})")
if __name__ == "__main__":
    if os.getuid() != 0:
        print("Requires root privilages :/ run with sudo ")
        sys.exit(1)
    cmd_parser = ArgumentParser(epilog = "Simple network scanner v1")
    cmd_parser.add_argument("-r","--ip-range",required = True,help = "target ip range")
    parsed_args = cmd_parser.parse_args()
    if parsed_args.ip_range:
        scan_network(parsed_args.ip_range)
