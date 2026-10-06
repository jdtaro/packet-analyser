from scapy.all import rdpcap, IP, TCP, ARP
from collections import Counter, defaultdict
import sys

SYN_THRESHOLD = 100
PORT_SCAN_THRESHOLD = 20

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
    synack_counter = Counter()

    for packet in packets:
        if packet.haslayer(IP):
            sources[packet[IP].src] += 1
            #print(packet[IP].dst)
            if packet.haslayer(TCP):
                flag = packet[TCP].flags
                if flag == "S":
                    syn_counter[packet[IP].src] += 1
                elif flag == "SA":
                    synack_counter[packet[IP].dst] += 1

    return sources, syn_counter, synack_counter


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

        
def check_syn_flood(packets, my_ip, window = 5, threshold=SYN_THRESHOLD):
    times = defaultdict(list)

    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(TCP) and packet[TCP].flags == "S": #only capture SYN and not SYN-ACK
            if packet[IP].dst == my_ip: #filter to only incoming traffic
                times[packet[IP].src].append(float(packet.time)) #add capture time to list for its source IP

    for ip, ts in times.items():
        ts.sort() #order incase capture wasnt ordered
        for i in range(threshold, len(ts)):
            if ts[i] - ts[i - threshold] <= window: #if threshhold + 1 SYN arrived within windown, flood
                print(f"ALERT: {ip} sent {len(ts)} SYNs within {window}s (at t={ts[i]:.2f})")
                break #terminal gets flooded if no break

def syn_ratio(syn_counter, synack_counter):
    total_syn = sum(syn_counter.values())
    total_synack = sum(synack_counter.values())

    print(f"Total SYN: {total_syn}, Total SYN-ACK: {total_synack}")
    if total_synack:
        print(f"Overall SYN:SYN-ACK ratio: {total_syn / total_synack:.2f}")
    else:
        print(f"No SYN-ACK's seen.")


def check_port_scan(packets, my_ip, threshold=PORT_SCAN_THRESHOLD):
    hit_ports = defaultdict(set)

    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(TCP) and packet[TCP].flags == "S":
            src = packet[IP].src
            if src == my_ip:
                continue
            hit_ports[src].add((packet[IP].dst, packet[TCP].dport))

    for ip, targets in hit_ports.items():
        ports = {port for _, port in targets} #vertical, many ports 1 host
        hosts = {host for host, _ in targets} #horizontal, many hosts, 1 port, should always be 1 as not network wide tests?
        if len(ports) > threshold:
            print(f"ALERT: possible port scan from {ip}: "
                  f"{len(ports)} distinct ports scross {len(hosts)} host(s)")

# do we want a summary?
#print(f"Busiest IP sources: {sources.most_common(5)}\n")
#print(f"Busiest SYN sources: {syn_counter.most_common(5)}\n")


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <file.pcap> <your_ip>")
        sys.exit(1)

    packets = load_packets(sys.argv[1])
    sources, syn_counter, synack_counter = traffic(packets)
    my_ip=sys.argv[2]

    check_arp_spoofing(packets)
    check_syn_flood(packets, my_ip) #fake_synflood.pcap uses 10.0.0.5
    syn_ratio(syn_counter, synack_counter)
    check_port_scan(packets, my_ip)

if __name__ == "__main__":
    main()