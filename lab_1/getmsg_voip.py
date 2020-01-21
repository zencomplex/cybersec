from scapy.all import *
import sys

ip_addr = sys.argv[1]

def get_message (packet):
    if packet[IP].src == ip_addr:
        print(packet[IP].src + " -> " + chr(packet[RTP].sequence))

sniff(filter='ip', prn=get_message)
