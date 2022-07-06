#!/usr/bin/python3

# use `sudo python3 sniffer.py` to run the code.

from scapy.all import *

iface_list=['br-3143c45cf389', 'enp0s3']

def print_pkt(pkt):
    pkt.show()

pkt = sniff(iface=iface_list, filter='icmp', prn=print_pkt)
