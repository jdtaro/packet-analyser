from scapy.all import rdpcap, IP, TCP, ARP
from collections import Counter
import sys

SYN_THRESHOLD = 100

#file = "fake_synflood.pcap"
#file = "testCapture.pcap"
#file = "arp_spoof.pcap"

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <file.pcap>")
    sys.exit(1)
print(f"Loading {sys.argv[1]}. Please wait, this may take longer depending on amount of recorded packets within the .pcap")
packets = rdpcap(sys.argv[1])
print(f"Loaded {sys.argv[1]}, reading {len(packets)}\n")

sources = Counter()
syn_counter = Counter()
seen = {} #list of mac addresses we've come across mapped to IPs

for packet in packets:
    if packet.haslayer(IP):
        sources[packet[IP].src] += 1
        if packet.haslayer(TCP) and packet[TCP].flags == "S":
            syn_counter[packet[IP].src] += 1

    if packet.haslayer(ARP) and packet[ARP].op == 2:
        psrc = packet[ARP].psrc #ip
        hwsrc = packet[ARP].hwsrc #mac

        if psrc not in seen:
            seen[psrc] = hwsrc
        elif seen[psrc] != hwsrc:
            print(f"ALERT: {psrc} was {seen[psrc]} but is now {hwsrc}\n")
            seen[psrc] = hwsrc

        

for ip, count in syn_counter.items():
    if count > SYN_THRESHOLD:
        print(f"ALERT: {ip} sent {count} packets (SYN threshold {SYN_THRESHOLD})\n")

print(f"Busiest IP sources: {sources.most_common(5)}\n")
print(f"Busiest SYN sources: {syn_counter.most_common(5)}\n")
