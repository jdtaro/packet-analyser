from scapy.all import rdpcap, IP, TCP, ARP
from collections import Counter
import sys

SYN_THRESHOLD = 100

#file = "fake_synflood.pcap"
#file = "testCapture.pcap"
#file = "arp_spoof.pcap"

def load_packets(path):
    print(f"Loading {path}. Please wait, this may take longer depending on amount of recorded packets within the .pcap")
    packets = rdpcap(path)
    print(f"Loaded {path}, reading {len(packets)}\n")
    return packets


def traffic(packets):
    sources = Counter()
    syn_counter = Counter()

    for packet in packets:
        if packet.haslayer(IP):
            sources[packet[IP].src] += 1
            if packet.haslayer(TCP) and packet[TCP].flags == "S":
                syn_counter[packet[IP].src] += 1

    return sources, syn_counter


def check_arp_spoofing(packets):
    seen = {} #list of mac addresses we've come across mapped to IPs

    for packet in packets:
        if packet.haslayer(ARP) and packet[ARP].op == 2:
            psrc = packet[ARP].psrc #ip
            hwsrc = packet[ARP].hwsrc #mac

            if psrc not in seen:
                seen[psrc] = hwsrc
            elif seen[psrc] != hwsrc:
                print(f"ALERT: {psrc} was {seen[psrc]} but is now {hwsrc}\n")
                seen[psrc] = hwsrc

        
def check_syn_flood(syn_counter, threshold=SYN_THRESHOLD):
    for ip, count in syn_counter.items():
        if count > threshold:
            print(f"ALERT: {ip} sent {count} packets (SYN threshold {threshold})\n")

# do we want a summary?
#print(f"Busiest IP sources: {sources.most_common(5)}\n")
#print(f"Busiest SYN sources: {syn_counter.most_common(5)}\n")


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file.pcap>")
        sys.exit(1)

    packets = load_packets(sys.argv[1])
    sources, syn_counter = traffic(packets)

    check_arp_spoofing(packets)
    check_syn_flood(syn_counter)

if __name__ == "__main__":
    main()