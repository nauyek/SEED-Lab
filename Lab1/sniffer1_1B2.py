#! /usr/bin/python3

from scapy.all import *

iface_list = ['br-3143c45cf389']
def print_pkt(pkt):
    pkt.show()
# Capture any TCP packet that comes from a particular IP and with a destination port number 23(Telnet).
plt = sniff(iface=iface_list, filter='src host 10.9.0.5 and tcp and src port 23', prn=print_pkt)
