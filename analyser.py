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

PORT_SCAN_THRESHOLD = 20 #testCapture.pcap triggers at 0
HOST_SCAN_THRESHOLD = 20 #testCapture.pcap triggers at 15
HOST_SCAN_WINDOW = 5

SYN = 0x02
ACK = 0x10

def is_syn(tcp) -> bool:
    flags = int(tcp.flags)
    return (flags & (SYN|ACK)) == SYN #mask, SYN is set and ACK isnt

def is_synack(tcp) -> bool:
    flags = int(tcp.flags)
    return (flags & (SYN|ACK)) == (SYN|ACK)

def max_distinct_in_window(events, window):
    '''events: sorted list of (time, value)
    Returns the most distinct values in any window of 'window' seconds.
    '''
    best = 0
    start = 0
    for end in range(len(events)):
        while events[end][0] - events[start][0] > window:
            start += 1
        distinct = {value for _, value in events[start:end + 1]}
        best = max(best, len(distinct))
    return best

#file = "fake_synflood.pcap"
#file = "testCapture.pcap"
#file = "arp_spoof.pcap"

def load_packets(path):
    print(f"Loading {path}. Please wait, this may take longer depending on amount of recorded packets within the .pcap")
    packets = rdpcap(path)
    print(f"Loaded {path}, reading {len(packets)}\n")
    return packets


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




def check_port_scan(packets, port_threshold=PORT_SCAN_THRESHOLD, host_threshold=HOST_SCAN_THRESHOLD, window=HOST_SCAN_WINDOW):
    """
    Detects vertical and horizontal TCP SYN scans within a "window" timeframe.

    Groups the SYN packets by source IP, then flags a source if it has probed either:
    - more than 'port_threshold' distinct ports on a single host (vertical scan)
    - the same port on more than 'host_threshold' distinct hosts (horizontal scan)

    Returns a list of Finding objects.
    """
    targets = defaultdict(set)
    horizontal_piles = defaultdict(list)
    vertical_piles = defaultdict(list)

    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(TCP) and is_syn(packet[TCP]):
            src = packet[IP].src
            dst = packet[IP].dst
            dport = packet[TCP].dport
            targets[src].add((dst, dport))
            horizontal_piles[(src, dport)].append((float(packet.time), dst))
            vertical_piles[(src, dst)].append((float(packet.time),dport))

    findings = []
    #horizontal scan (now windowed)
    for (src, dport), events in horizontal_piles.items():
        events.sort()
        distinct = max_distinct_in_window(events,window)
        #print(src, dport, "distinct in window:", distinct, "total events: ", len(events))
        if distinct > host_threshold:
            findings.append(Finding(
                kind="Horizontal port scan",
                attacker=src,
                victim= f"{distinct} hosts",
                evidence= f"port {dport} probed on {distinct} hosts within {window}s"
            ))

    #vertical scan (now windowed)
    for (src, dst), events in vertical_piles.items():
        events.sort()
        distinct = max_distinct_in_window(events, window)
        #print(src, dst, "distinct in window:", distinct, "total events: ", len(events))
        if distinct > port_threshold:
            findings.append(Finding(
                kind= "Vertical port scan",
                attacker= src,
                victim= dst,
                evidence= f"{distinct} distinct ports probed within {window}s."
            ))
    return findings

    


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <file.pcap> <your_ip>")
        sys.exit(1)

    packets = load_packets(sys.argv[1])

    check_arp_spoofing(packets)
    check_syn_flood_simple(packets) #fake_synflood.pcap uses 10.0.0.5
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