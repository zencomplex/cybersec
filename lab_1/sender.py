from scapy.all import *
import sys

ip_addr = sys.argv[1]
str = sys.argv[2]

for char in str:
     num = ord(char)
     pkt = IP(dst=ip_addr, tos = 17)/TCP(seq = ord(char))/ICMP()
     send(pkt)
