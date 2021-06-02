#!/usr/bin/python3
from scapy.all import *

udp = UDP(sport=7070, dport=9090)
udp.len = 104
ip = IP(src="1.2.3.4", dst="10.0.2.5") 
ip.id = 1000
ip.frag = 0
ip.flags = 1

payload = "A" * 32 

pkt = ip/udp/payload
pkt[UDP].chksum = 0
send(pkt,verbose=0)

ip = IP(src="1.2.3.4", dst="10.0.2.5") 
ip.id = 1000
ip.frag = 5
ip.flags = 1
ip.proto = 17
pkt = ip/payload
send(pkt,verbose=0)

ip = IP(src="1.2.3.4", dst="10.0.2.5") 
ip.id = 1000
ip.frag = 9
ip.flags = 0
ip.proto = 17
pkt = ip/payload
send(pkt,verbose=0)

print("Finish Sending Packets!")