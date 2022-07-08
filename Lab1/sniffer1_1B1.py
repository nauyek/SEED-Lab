#! /usr/bin/python3

from scapy.all import *

iface_list=['br-3143c45cf389', 'enp0s3']
def print_pkt(pkt):
    pkt.show()
# Capture only the ICMP packet
pkt = sniff(iface=iface_list, filter='icmp', prn=print_pkt)
