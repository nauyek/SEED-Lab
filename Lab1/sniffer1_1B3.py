#! /usr/bin/python3

from scapy.all import *

iface_list = ['br-3143c45cf389']
def print_pkt(pkt):
    pkt.show()
# Capture packets comes from or go to a particular subnet
pkt = sniff(iface=iface_list, filter='net 10.9.0.0/24', prn=print_pkt)
