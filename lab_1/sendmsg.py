from scapy.all import *
import sys

ip_addr = sys.argv[1]
str = sys.argv[2]

for char in str:
     num = ord(char)
     pkt = Ether()/ARP(psrc = "192.168.1.91", pdst = ip_addr, hwlen = num)
     sendp(pkt)
