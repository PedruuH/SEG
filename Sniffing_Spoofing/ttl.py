from scapy.all import *

for i in range(1,20):
	a = IP()
	a.dst = '200.19.146.101' #ip da ufu.br
	a.ttl = i
	b = ICMP()
	send(a/b)


