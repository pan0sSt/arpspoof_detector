#!/usr/bin/env python

import scapy.all as scapy     # handle tasks like scanning and network discovery
from scapy.layers import http # sending / receiving of HTTP packets natively


# function that returns MAC address of selected IP
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip) # ARP object creation, asks who has target IP
    broadcast   = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # Ethernet object creation, set destination MAC to broadcast MAC
    arp_request_broadcast = broadcast/arp_request # Combine into a single packet
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] # Send packets with custom Ether, send packet and receive response. "timeout": Time to wait for response
    try:
        return answered_list[0][1].hwsrc
    except IndexError:
        pass

# main function
def sniff(interface):
    # iface: interface
    # store: store packets
    # prn: callback function
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

# function that processes the sniffed packets
def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:  # op=2: packet is response, not request
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc

            if real_mac != response_mac:
                print("[!] YOU ARE UNDER ATTACK [!]")
        except IndexError:
            pass

sniff("eth0")