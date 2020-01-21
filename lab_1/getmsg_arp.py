from scapy.all import *
import sys

str=sys.argv[1]

def get_packet(packet):
    if packet.haslayer(ARP) and packet[ARP].psrc == str:
        print(packet[ARP].psrc + " -> " + chr(packet[ARP].hwlen))

sniff(filter="arp", prn=get_packet)
