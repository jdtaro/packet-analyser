from scapy.all import Ether, IP, TCP, ARP, wrpcap

# 500 SYN packets from a fake attacker to a fake server
# Each uses a different source port as real connection attempts would
# DO NOT CHANGE src AND dst TO REAL IPS, KEEP LOCAL ONES

#packets = [
#    Ether() / IP(src="10.0.0.99", dst="10.0.0.5") / TCP(sport=1024 + i, dport=80, flags="S")
#    for i in range(500) # change the amount of packets to generate
#]

packets = [
    Ether(dst="cc:cc:cc:cc:cc:cc") / ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:aa", pdst="10.0.0.5"),
    Ether(dst="cc:cc:cc:cc:cc:cc") / ARP(op=2, psrc="10.0.0.1", hwsrc="bb:bb:bb:bb:bb:bb", pdst="10.0.0.5"),
]

wrpcap("arp_spoof.pcap", packets)
print(f"Wrote {len(packets)} packets to fake_synflood.pcap")