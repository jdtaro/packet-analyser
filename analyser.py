from scapy.all import rdpcap, IP, TCP, ARP
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Optional
import sys

@dataclass
class Finding:
    kind: str
    attacker: str
    victim: str
    evidence: str
    time: Optional[float] = None

SYN_THRESHOLD = 100
SYN_WINDOW = 5

PORT_SCAN_THRESHOLD = 20
HOST_SCAN_THRESHOLD = 20 #testCapture.pcap triggers at 15

SYN = 0x02
ACK = 0x10

def is_syn(tcp) -> bool:
    flags = int(tcp.flags)
    return (flags & (SYN|ACK)) == SYN #mask, SYN is set and ACK isnt

def is_synack(tcp) -> bool:
    flags = int(tcp.flags)
    return (flags & (SYN|ACK)) == (SYN|ACK)

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

        
def check_syn_flood_simple(packets, window = SYN_WINDOW, threshold=SYN_THRESHOLD):
    """
    Detects bursts of SYNs aimed at a single host.

    For each SYN, counts how many go to the same host within 'window'seconds.
    Flagged if that count passes 'threshold', from any number of sources.

    Returns a list of Finding objects.
    """
    incomming = defaultdict(list)

    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(TCP) and is_syn(packet[TCP]):
            incomming[packet[IP].dst].append((float(packet.time), packet[IP].src))

    findings = []
    for ip, ts in incomming.items():
        for start_time, _ in ts:
            in_window = [(time, src) for time, src in ts
                         if start_time <= time <= start_time + window]

            if len(in_window) > threshold:
                sources = {src for _, src in in_window}
                findings.append(Finding(
                    kind= "SYN Flood",
                    attacker= f"{len(sources)} source(s)",
                    victim= ip,
                    evidence= f"{len(in_window)} SYNs within {window}s from {len(sources)}",
                    time=start_time
                ))
                break
    return findings


def check_syn_flood(packets, window = SYN_WINDOW, threshold=SYN_THRESHOLD):
    """
    Detects bursts of SYNs aimed at a single host. Refactored improved version.

    For each SYN, counts how many go to the same host within 'window'seconds.
    Flagged if that count passes 'threshold', from any number of sources.

    Returns a list of Finding objects.
    """
    incomming = defaultdict(list)

    # collect every SYN grouped by destination
    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(TCP) and is_syn(packet[TCP]):
            dest = packet[IP].dst
            source = packet[IP].src
            time = float(packet.time)
            incomming[dest].append((time, source))

    # for each destination, slide a window along its SYNs
    findings = []
    for dest in incomming:
        events = incomming[dest]
        events.sort()

        # split into two lists that line up
        times = []
        sources = []
        for event in events:
            times.append(event[0])
            sources.append(event[1])

        start = 0
        for end in range(len(times)): #right edge that moves along one SYN at a time
            while times[end] - times[start] > window: #if too wide, move left forwrds
                start += 1
            count = end - start + 1 #everything from start to end is in the window
            if count > threshold:
                unique_srcs = set() #find who sent the SYNs
                for i in range(start, end + 1):
                    unique_srcs.add(sources[i])

                if len(unique_srcs) == 1:
                    for src_ip in unique_srcs:
                        attacker = src_ip #might be better way to get this
                else:
                    attacker = f"{len(unique_srcs)} sources"

                findings.append(Finding(
                    kind= "SYN Flood",
                    attacker= attacker,
                    victim = dest,
                    evidence= f"{count} SYNs in {window}s from {len(unique_srcs)} source(s)",
                    time= times[end]
                ))
                break #will stop after the threshold has been hit
    return findings



def syn_ratio(syn_counter, synack_counter):
    total_syn = sum(syn_counter.values())
    total_synack = sum(synack_counter.values())

    print(f"Total SYN: {total_syn}, Total SYN-ACK: {total_synack}")
    if total_synack:
        print(f"Overall SYN:SYN-ACK ratio: {total_syn / total_synack:.2f}")
    else:
        print(f"No SYN-ACK's seen.")




def check_port_scan(packets, port_threshold=PORT_SCAN_THRESHOLD, host_threshold=HOST_SCAN_THRESHOLD):
    """
    Detects vertical and horizontal TCP SYN scans.

    Groups the SYN packets by source IP, then flags a source if it has probed either:
    - more than 'port_threshold' distinct ports on a single host (vertical scan)
    - the same port on more than 'host_threshold' distinct hosts (horizontal scan)

    Returns a list of Finding objects.
    """
    targets = defaultdict(set)

    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(TCP) and is_syn(packet[TCP]):
            targets[packet[IP].src].add((packet[IP].dst, packet[TCP].dport))

    findings = []
    for src, pairs in targets.items():
        ports_per_host = defaultdict(set)
        hosts_per_port = defaultdict(set)

        for host, port in pairs:
            ports_per_host[host].add(port)
            hosts_per_port[port].add(host)

        # vertical scan
        for host, ports in ports_per_host.items():
            if len(ports) > port_threshold:
                findings.append(Finding(
                    kind= "Vertical port scan",
                    attacker= src,
                    victim= host,
                    evidence= f"{len(ports)} distinct ports probed."
                ))

        # horizontal scan
        for port, hosts in hosts_per_port.items():
            #print(f"DEBUG {src} port {port}: {len(hosts)} hosts")
            if len(hosts) > host_threshold:
                findings.append(Finding(
                    kind= "Horizontal port scan",
                    attacker= src,
                    victim= f"{len(hosts)} hosts",
                    evidence= f"port {port} probed by {len(hosts)} hosts."
                ))
    return findings

    


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <file.pcap> <your_ip>")
        sys.exit(1)

    packets = load_packets(sys.argv[1])
    sources, syn_counter, synack_counter = traffic(packets)
    my_ip=sys.argv[2]

    check_arp_spoofing(packets)
    check_syn_flood_simple(packets) #fake_synflood.pcap uses 10.0.0.5
    syn_ratio(syn_counter, synack_counter)
    check_port_scan(packets)


    #FOR DEBUGGING
    targets1 = defaultdict(set)
    for p in packets:
        if p.haslayer(IP) and p.haslayer(TCP) and is_syn(p[TCP]):
            targets1[p[IP].src].add((p[IP].dst, p[TCP].dport))
    for src, pairs in targets1.items():
        print(src, "hosts:", len({h for h, _ in pairs}), "ports:", len({i for _, i in pairs}))

    for f in check_syn_flood_simple(packets):
        print(f"ALERT SIMPLE [{f.kind}] {f.attacker} -> {f.victim}: {f.evidence} {f.time}")

    for f in check_syn_flood(packets):
            print(f"ALERT [{f.kind}] {f.attacker} -> {f.victim}: {f.evidence} {f.time}")

    for f in check_port_scan(packets):
            print(f"ALERT [{f.kind}] {f.attacker} -> {f.victim}: {f.evidence}")    

if __name__ == "__main__":
    main()