from scapy.all import *
import sys


def get_packet(packet):
    if packet[IP].tos == 17:
        print(chr(packet[TCP].seq))

print("[+] Started Listener\n")

packet = sniff(iface="wlan0", filter='ip', prn=get_packet)

wrpcap('evil.pcap', packet)
