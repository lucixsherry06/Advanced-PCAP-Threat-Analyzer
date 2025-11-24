#!/usr/bin/env python3
"""
main.py

Detects multiple network threats from a pcap:
 - ARP spoofing (IP -> multiple MACs)
 - Port scanning (many unique dst ports from one src in a short window)
 - SYN flood detection (many SYNs with low SYN-ACK/ACK responses)
 - DNS tunneling / suspicious DNS (long qnames, base64-like labels, very high DNS rate)
 - ICMP flood (many ICMP echo requests in short window)
 - Suspicious IP behavior (talking to many unique endpoints)

Usage:
  python3 main.py --pcap lab_capture.pcap --out report.txt

Dependencies:
  pip install scapy
"""

import argparse
import csv
import time
import re
from collections import defaultdict, deque, Counter
from scapy.all import rdpcap, ARP, TCP, IP, DNS, UDP, ICMP

# -----------------------------
# Configurable thresholds
# -----------------------------
PORTSCAN_UNIQUE_PORTS = 25          # unique dst ports in window => port scan
PORTSCAN_WINDOW = 10.0              # seconds
SYN_FLOOD_SYN_THRESHOLD = 150       # number of SYNs in window to flag
SYN_FLOOD_WINDOW = 10.0             # seconds
SYN_FLOOD_MIN_SYNACK_RATIO = 0.2    # if SYN-ACKs / SYNs < this, suspicious
DNS_LONG_QNAME = 80                 # qname length considered suspicious
DNS_HIGH_RATE = 60                  # number of DNS queries in DNS_WINDOW to flag
DNS_WINDOW = 60.0                   # seconds
ICMP_FLOOD_THRESHOLD = 200          # ICMP reqs in window
ICMP_WINDOW = 10.0                  # seconds
SUSPICIOUS_HOSTS_UNIQUE_DST = 50    # unique destination IPs in window => suspicious
SUSPICIOUS_HOSTS_WINDOW = 60.0

BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
BASE64_MIN_LEN = 16
BASE64_MIN_RATIO = 0.65

# -----------------------------
# Utility helpers
# -----------------------------
def is_base64_like(s):
    if not s:
        return False
    # remove dots/hyphens often present in domain labels
    s_clean = re.sub(r'[\.\-]', '', s)
    if len(s_clean) < BASE64_MIN_LEN:
        return False
    count = sum(1 for ch in s_clean if ch in BASE64_CHARS)
    return (count / len(s_clean)) >= BASE64_MIN_RATIO

def timestamp_str(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))

# -----------------------------
# Detection implementations
# -----------------------------
def detect_arp(packets):
    ip_to_macs = defaultdict(set)
    for pkt in packets:
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            # ARP 'is-at' typically op==2, but we'll map psrc->hwsrc
            try:
                ip = arp.psrc
                mac = arp.hwsrc.lower()
                ip_to_macs[ip].add(mac)
            except Exception:
                continue
    rows = []
    events = []
    for ip, macs in ip_to_macs.items():
        rows.append((ip, ";".join(sorted(macs))))
        if len(macs) > 1:
            events.append((ip, list(sorted(macs))))
    return rows, events

def detect_port_scans(packets):
    # For each src IP keep deque of (ts, dstport) and set of ports
    windows = defaultdict(lambda: deque())
    ports_set = defaultdict(set)
    portscan_events = []
    portscan_csv = []
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            tcp = pkt[TCP]
            ip = pkt[IP]
            ts = float(pkt.time)
            src = ip.src
            dst = ip.dst
            dport = int(tcp.dport)
            # we consider SYNs mainly as scan indicators; include others optionally
            flags = int(tcp.flags)
            syn_flag = (flags & 0x02) != 0
            if not syn_flag:
                continue
            windows[src].append((ts, dport))
            ports_set[src].add(dport)
            portscan_csv.append((timestamp_str(ts), src, dst, dport))
            # cleanup window
            while windows[src] and (ts - windows[src][0][0]) > PORTSCAN_WINDOW:
                _, oldp = windows[src].popleft()
                # recompute ports_set[src] cheaply
                current_ports = set(p for (_, p) in windows[src])
                ports_set[src] = current_ports
            if len(ports_set[src]) >= PORTSCAN_UNIQUE_PORTS:
                # record event
                start_ts = windows[src][0][0] if windows[src] else ts
                end_ts = windows[src][-1][0] if windows[src] else ts
                sample_ports = sorted(list(ports_set[src]))[:20]
                portscan_events.append((src, timestamp_str(start_ts), timestamp_str(end_ts), len(ports_set[src]), sample_ports))
                windows[src].clear()
                ports_set[src].clear()
    return portscan_events, portscan_csv

def detect_syn_flood(packets):
    # Track per-src SYNs count and SYN-ACKs received back
    syn_windows = defaultdict(lambda: deque())
    syn_counts = defaultdict(int)
    synack_counts = defaultdict(int)
    syn_csv = []
    syn_events = []
    # We will also map tuple (src,dst) to syn counts to compute ratios per attacker->victim
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            tcp = pkt[TCP]
            ip = pkt[IP]
            ts = float(pkt.time)
            src = ip.src
            dst = ip.dst
            flags = int(tcp.flags)
            syn_flag = (flags & 0x02) != 0
            ack_flag = (flags & 0x10) != 0
            # attacker sending SYNs
            if syn_flag and not ack_flag:
                syn_windows[src].append(ts)
                syn_counts[src] += 1
                syn_csv.append((timestamp_str(ts), src, dst, int(tcp.dport)))
                # cleanup window
                while syn_windows[src] and (ts - syn_windows[src][0]) > SYN_FLOOD_WINDOW:
                    syn_windows[src].popleft()
                # if many SYNs in window, flag candidate
                if len(syn_windows[src]) >= SYN_FLOOD_SYN_THRESHOLD:
                    # compute a crude SYN-ACK ratio by searching packets: expensive, so we use synack_counts cached below
                    ratio = (synack_counts.get(src, 0) / len(syn_windows[src])) if len(syn_windows[src])>0 else 0.0
                    syn_events.append((src, timestamp_str(syn_windows[src][0]), timestamp_str(syn_windows[src][-1]), len(syn_windows[src]), round(ratio, 3)))
                    syn_windows[src].clear()
                    syn_counts[src] = 0
                    synack_counts[src] = 0
            # if packet is SYN-ACK coming back to src (rarely seen with IP flipping), increment synack for corresponding src
            if syn_flag and ack_flag:
                # this is a SYN-ACK from dst->src; treat as response to src's SYNs
                # track by destination (the original client will be tcp.dst)
                # we'll give credit to the intended recipient (ip.dst)
                synack_counts[dst] = synack_counts.get(dst, 0) + 1
    return syn_events, syn_csv

def detect_dns_anomalies(packets):
    queries_by_src = defaultdict(list)
    dns_csv = []
    dns_events = []
    for pkt in packets:
        # DNS usually runs over UDP/53, but can be over TCP. We check for DNS layer.
        if pkt.haslayer(DNS) and pkt.haslayer(IP):
            dns = pkt[DNS]
            ip = pkt[IP]
            ts = float(pkt.time)
            # only queries (qr==0)
            if getattr(dns, "qr", None) == 0 and dns.qd is not None:
                try:
                    qname = bytes(dns.qd.qname).decode('utf-8', errors='ignore').rstrip('.')
                except Exception:
                    qname = str(dns.qd.qname)
                qtype = int(dns.qd.qtype) if hasattr(dns.qd, "qtype") else 0
                src = ip.src
                dst = ip.dst
                queries_by_src[src].append((ts, qname, qtype, dst))
                dns_csv.append((timestamp_str(ts), src, dst, qname, qtype))
    # analyze
    for src, lst in queries_by_src.items():
        if not lst:
            continue
        lst_sorted = sorted(lst, key=lambda x: x[0])
        # frequency window check
        window = deque()
        flagged_high_rate = False
        for ts, qname, qtype, dst in lst_sorted:
            window.append(ts)
            while window and (ts - window[0]) > DNS_WINDOW:
                window.popleft()
            if len(window) >= DNS_HIGH_RATE:
                dns_events.append(("high_rate", src, len(window), timestamp_str(ts), lst_sorted[:5]))
                flagged_high_rate = True
                break
        # long qname / base64-like checks
        suspicious_q = []
        for ts, qname, qtype, dst in lst_sorted:
            if len(qname) >= DNS_LONG_QNAME:
                suspicious_q.append((timestamp_str(ts), qname, "long"))
            else:
                # check labels for base64-like content
                parts = qname.split('.')
                for part in parts:
                    if is_base64_like(part):
                        suspicious_q.append((timestamp_str(ts), qname, "base64-like"))
                        break
        if suspicious_q:
            dns_events.append(("suspicious_qnames", src, suspicious_q[:10]))
        # if both flagged_high_rate and suspicious_q, keep both events
    return dns_events, dns_csv

def detect_icmp_flood(packets):
    icmp_windows = defaultdict(lambda: deque())
    icmp_csv = []
    icmp_events = []
    for pkt in packets:
        if pkt.haslayer(ICMP) and pkt.haslayer(IP):
            icmp = pkt[ICMP]
            ip = pkt[IP]
            ts = float(pkt.time)
            src = ip.src
            # focus on echo-request (type 8) for floods
            if int(icmp.type) == 8:
                icmp_windows[src].append(ts)
                icmp_csv.append((timestamp_str(ts), src, ip.dst))
                while icmp_windows[src] and (ts - icmp_windows[src][0]) > ICMP_WINDOW:
                    icmp_windows[src].popleft()
                if len(icmp_windows[src]) >= ICMP_FLOOD_THRESHOLD:
                    icmp_events.append((src, timestamp_str(icmp_windows[src][0]), timestamp_str(icmp_windows[src][-1]), len(icmp_windows[src])))
                    icmp_windows[src].clear()
    return icmp_events, icmp_csv

def detect_suspicious_hosts(packets):
    # hosts that communicate with many unique dst IPs in a short window
    windows = defaultdict(lambda: deque())      # src -> deque of (ts,dst)
    unique_sets = defaultdict(set)
    suspect_events = []
    suspect_csv = []
    for pkt in packets:
        if pkt.haslayer(IP):
            ip = pkt[IP]
            ts = float(pkt.time)
            src = ip.src
            dst = ip.dst
            windows[src].append((ts, dst))
            unique_sets[src].add(dst)
            suspect_csv.append((timestamp_str(ts), src, dst))
            # cleanup
            while windows[src] and (ts - windows[src][0][0]) > SUSPICIOUS_HOSTS_WINDOW:
                _, olddst = windows[src].popleft()
                current = set(d for (_, d) in windows[src])
                unique_sets[src] = current
            if len(unique_sets[src]) >= SUSPICIOUS_HOSTS_UNIQUE_DST:
                suspect_events.append((src, timestamp_str(windows[src][0][0]), timestamp_str(windows[src][-1][0]), len(unique_sets[src])))
                windows[src].clear()
                unique_sets[src].clear()
    return suspect_events, suspect_csv

# -----------------------------
# CSV writer
# -----------------------------
def write_csv(filename, header, rows):
    with open(filename, "w", newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)

# -----------------------------
# Main
# -----------------------------
def main():
    ap = argparse.ArgumentParser(description="Advanced PCAP Threat Analyzer")
    ap.add_argument("--pcap", required=True, help="Input pcap file (pcap/pcapng)")
    ap.add_argument("--out", default="report.txt", help="Text report output file")
    ap.add_argument("--verbose", action="store_true", help="Verbose output")
    args = ap.parse_args()

    print("[*] Loading pcap:", args.pcap)
    packets = rdpcap(args.pcap)
    print("[*] Packets loaded:", len(packets))

    # ARP
    print("[*] Running ARP analysis...")
    arp_rows, arp_events = detect_arp(packets)
    write_csv("arp_map.csv", ["ip", "macs"], arp_rows)

    # Port scans
    print("[*] Running port scan analysis...")
    portscan_events, portscan_csv = detect_port_scans(packets)
    write_csv("portscan.csv", ["time", "src", "dst", "dstport"], portscan_csv)

    # SYN flood
    print("[*] Running SYN flood analysis...")
    syn_events, syn_csv = detect_syn_flood(packets)
    write_csv("syn_events.csv", ["time", "src", "dst", "dstport"], syn_csv)

    # DNS anomalies
    print("[*] Running DNS anomaly analysis...")
    dns_events, dns_csv = detect_dns_anomalies(packets)
    write_csv("dns_events.csv", ["time", "src", "dst", "qname", "qtype"], dns_csv)

    # ICMP flood
    print("[*] Running ICMP flood analysis...")
    icmp_events, icmp_csv = detect_icmp_flood(packets)
    write_csv("icmp_events.csv", ["time", "src", "dst"], icmp_csv)

    # Suspicious hosts
    print("[*] Running suspicious-hosts analysis...")
    suspect_events, suspect_csv = detect_suspicious_hosts(packets)
    write_csv("suspicious_ips.csv", ["time", "src", "dst"], suspect_csv)

    # Compose report
    now = timestamp_str(time.time())
    with open(args.out, "w", encoding='utf-8') as rpt:
        rpt.write(f"Advanced PCAP Threat Analyzer Report\nGenerated: {now}\nSource PCAP: {args.pcap}\n\n")
        # ARP
        rpt.write("== ARP Analysis ==\n")
        if arp_events:
            rpt.write("Potential ARP spoofing (IP mapped to multiple MACs):\n")
            for ip, macs in arp_events:
                rpt.write(f" - {ip} -> {', '.join(macs)}\n")
            rpt.write("See arp_map.csv for full mapping.\n\n")
        else:
            rpt.write("No ARP IP->multiple-MAC anomalies detected.\n\n")

        # Port scans
        rpt.write("== Port Scan Analysis ==\n")
        if portscan_events:
            rpt.write(f"Port-scan-like events detected: {len(portscan_events)}\n")
            for ev in portscan_events:
                src, s_ts, e_ts, count, sample = ev
                rpt.write(f" - {src} scanned ~{count} unique ports between {s_ts} and {e_ts}. Sample ports: {sample}\n")
            rpt.write("See portscan.csv for per-packet SYN logs.\n\n")
        else:
            rpt.write("No port-scan-like patterns detected.\n\n")

        # SYN flood
        rpt.write("== SYN Flood Analysis ==\n")
        if syn_events:
            rpt.write(f"SYN-flood-like events detected: {len(syn_events)}\n")
            for ev in syn_events:
                src, s_ts, e_ts, syn_count, synack_ratio = ev
                rpt.write(f" - {src} sent {syn_count} SYNs between {s_ts} and {e_ts}. SYN-ACK ratio approx {synack_ratio}\n")
            rpt.write("See syn_events.csv for per-SYN logs.\n\n")
        else:
            rpt.write("No SYN-flood-like patterns detected.\n\n")

        # DNS
        rpt.write("== DNS Analysis ==\n")
        if dns_events:
            for ev in dns_events:
                if ev[0] == "high_rate":
                    _, src, num, ts, sample = ev
                    rpt.write(f" - High DNS query rate from {src}: {num} queries within {DNS_WINDOW}s (sample shown in dns_events.csv)\n")
                elif ev[0] == "suspicious_qnames":
                    _, src, sq = ev
                    rpt.write(f" - Suspicious DNS QNAMEs from {src} (long/base64-like). Examples:\n")
                    for tstamp, qname, reason in sq:
                        rpt.write(f"    * {tstamp}: {qname} ({reason})\n")
            rpt.write("See dns_events.csv for full DNS query list.\n\n")
        else:
            rpt.write("No DNS anomalies detected.\n\n")

        # ICMP
        rpt.write("== ICMP Analysis ==\n")
        if icmp_events:
            for ev in icmp_events:
                src, s_ts, e_ts, count = ev
                rpt.write(f" - ICMP flood suspected from {src}: {count} echo-requests between {s_ts} and {e_ts}\n")
            rpt.write("See icmp_events.csv for per-packet records.\n\n")
        else:
            rpt.write("No ICMP flood detected.\n\n")

        # Suspicious hosts
        rpt.write("== Suspicious Hosts ==\n")
        if suspect_events:
            for ev in suspect_events:
                src, s_ts, e_ts, uniq = ev
                rpt.write(f" - {src} contacted {uniq} unique destinations between {s_ts} and {e_ts}\n")
            rpt.write("See suspicious_ips.csv for full logs.\n\n")
        else:
            rpt.write("No hosts contacting unusually many destinations detected.\n\n")

        rpt.write("== Recommendations ==\n")
        rpt.write(" - ARP spoofing: enable DHCP snooping & dynamic ARP inspection on switches; set static ARP for critical hosts.\n")
        rpt.write(" - Port scans/SYN floods: deploy IDS/IPS rules; rate-limit and block offending IPs; use SYN cookies on servers.\n")
        rpt.write(" - DNS anomalies: restrict DNS egress to approved resolvers; monitor long qnames and TXT records.\n")
        rpt.write(" - ICMP floods: rate-limit ICMP at perimeter; use ACLs to block abusive sources.\n")
        rpt.write(" - Suspicious hosts: isolate and investigate hosts contacting many endpoints; check for botnets/malware.\n")
        rpt.write("\nCSV logs generated:\n - arp_map.csv\n - portscan.csv\n - syn_events.csv\n - dns_events.csv\n - icmp_events.csv\n - suspicious_ips.csv\n")
    print(f"[+] Report written to {args.out}")
    print("[+] CSV logs written: arp_map.csv, portscan.csv, syn_events.csv, dns_events.csv, icmp_events.csv, suspicious_ips.csv")
    print("[+] Done.")

if __name__ == "__main__":
    main()
