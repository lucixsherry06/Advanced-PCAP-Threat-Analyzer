#!/usr/bin/env python3
"""
main.py

Advanced PCAP Analyzer with modular execution:
 - ARP spoofing
 - Port scanning
 - SYN flood detection
 - DNS anomalies
 - ICMP flood
 - Suspicious hosts
 - HTTP keyword detection
 - Top Talkers
 - Protocol distribution

Usage:
  python main.py --pcap sample.pcap --out report.txt --module all

Dependencies:
  pip install scapy
"""

import argparse
import csv
import time
import re
from collections import defaultdict, deque, Counter
from scapy.all import rdpcap, ARP, TCP, IP, DNS, UDP, ICMP, Raw

# -----------------------------
# Configurable thresholds
# -----------------------------
PORTSCAN_UNIQUE_PORTS = 25
PORTSCAN_WINDOW = 10.0
SYN_FLOOD_SYN_THRESHOLD = 150
SYN_FLOOD_WINDOW = 10.0
SYN_FLOOD_MIN_SYNACK_RATIO = 0.2
DNS_LONG_QNAME = 80
DNS_HIGH_RATE = 60
DNS_WINDOW = 60.0
ICMP_FLOOD_THRESHOLD = 200
ICMP_WINDOW = 10.0
SUSPICIOUS_HOSTS_UNIQUE_DST = 50
SUSPICIOUS_HOSTS_WINDOW = 60.0

BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
BASE64_MIN_LEN = 16
BASE64_MIN_RATIO = 0.65

HTTP_KEYWORDS = ["password","login","admin","cmd","token","flag","secret","pass","key"]

# -----------------------------
# Utility helpers
# -----------------------------
def is_base64_like(s):
    if not s:
        return False
    s_clean = re.sub(r'[\.\-]', '', s)
    if len(s_clean) < BASE64_MIN_LEN:
        return False
    count = sum(1 for ch in s_clean if ch in BASE64_CHARS)
    return (count / len(s_clean)) >= BASE64_MIN_RATIO

def timestamp_str(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))

def write_csv(filename, header, rows):
    with open(filename, "w", newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)

# -----------------------------
# Detection implementations
# -----------------------------
def detect_arp(packets):
    ip_to_macs = defaultdict(set)
    for pkt in packets:
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            try:
                ip = arp.psrc
                mac = arp.hwsrc.lower()
                ip_to_macs[ip].add(mac)
            except Exception:
                continue
    rows, events = [], []
    for ip, macs in ip_to_macs.items():
        rows.append((ip, ";".join(sorted(macs))))
        if len(macs) > 1:
            events.append((ip, list(sorted(macs))))
    return rows, events

def detect_port_scans(packets):
    windows = defaultdict(lambda: deque())
    ports_set = defaultdict(set)
    portscan_events, portscan_csv = [], []
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            tcp = pkt[TCP]; ip = pkt[IP]; ts = float(pkt.time)
            src = ip.src; dst = ip.dst; dport = int(tcp.dport)
            flags = int(tcp.flags)
            if (flags & 0x02) == 0: continue
            windows[src].append((ts, dport))
            ports_set[src].add(dport)
            portscan_csv.append((timestamp_str(ts), src, dst, dport))
            while windows[src] and (ts - windows[src][0][0]) > PORTSCAN_WINDOW:
                _, oldp = windows[src].popleft()
                ports_set[src] = set(p for (_, p) in windows[src])
            if len(ports_set[src]) >= PORTSCAN_UNIQUE_PORTS:
                start_ts = windows[src][0][0] if windows[src] else ts
                end_ts = windows[src][-1][0] if windows[src] else ts
                sample_ports = sorted(list(ports_set[src]))[:20]
                portscan_events.append((src, timestamp_str(start_ts), timestamp_str(end_ts), len(ports_set[src]), sample_ports))
                windows[src].clear(); ports_set[src].clear()
    return portscan_events, portscan_csv

def detect_syn_flood(packets):
    syn_windows = defaultdict(lambda: deque())
    syn_counts = defaultdict(int)
    synack_counts = defaultdict(int)
    syn_csv, syn_events = [], []
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            tcp = pkt[TCP]; ip = pkt[IP]; ts = float(pkt.time)
            src, dst = ip.src, ip.dst
            flags = int(tcp.flags)
            syn_flag, ack_flag = (flags & 0x02)!=0, (flags & 0x10)!=0
            if syn_flag and not ack_flag:
                syn_windows[src].append(ts); syn_counts[src] += 1
                syn_csv.append((timestamp_str(ts), src, dst, int(tcp.dport)))
                while syn_windows[src] and (ts - syn_windows[src][0]) > SYN_FLOOD_WINDOW:
                    syn_windows[src].popleft()
                if len(syn_windows[src]) >= SYN_FLOOD_SYN_THRESHOLD:
                    ratio = (synack_counts.get(src,0)/len(syn_windows[src])) if len(syn_windows[src])>0 else 0.0
                    syn_events.append((src, timestamp_str(syn_windows[src][0]), timestamp_str(syn_windows[src][-1]), len(syn_windows[src]), round(ratio,3)))
                    syn_windows[src].clear(); syn_counts[src]=0; synack_counts[src]=0
            if syn_flag and ack_flag:
                synack_counts[dst] = synack_counts.get(dst,0)+1
    return syn_events, syn_csv

def detect_dns_anomalies(packets):
    queries_by_src = defaultdict(list)
    dns_csv, dns_events = [], []
    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(IP):
            dns = pkt[DNS]; ip = pkt[IP]; ts = float(pkt.time)
            if getattr(dns,"qr",None)==0 and dns.qd is not None:
                try: qname = bytes(dns.qd.qname).decode('utf-8',errors='ignore').rstrip('.')
                except Exception: qname = str(dns.qd.qname)
                qtype = int(dns.qd.qtype) if hasattr(dns.qd,"qtype") else 0
                src,dst = ip.src, ip.dst
                queries_by_src[src].append((ts,qname,qtype,dst))
                dns_csv.append((timestamp_str(ts),src,dst,qname,qtype))
    for src,lst in queries_by_src.items():
        if not lst: continue
        lst_sorted = sorted(lst,key=lambda x:x[0])
        window = deque(); flagged_high_rate=False
        for ts,qname,qtype,dst in lst_sorted:
            window.append(ts)
            while window and (ts-window[0])>DNS_WINDOW: window.popleft()
            if len(window)>=DNS_HIGH_RATE:
                dns_events.append(("high_rate",src,len(window),timestamp_str(ts),lst_sorted[:5]))
                flagged_high_rate=True; break
        suspicious_q=[]
        for ts,qname,qtype,dst in lst_sorted:
            if len(qname)>=DNS_LONG_QNAME: suspicious_q.append((timestamp_str(ts),qname,"long"))
            else:
                for part in qname.split('.'):
                    if is_base64_like(part): suspicious_q.append((timestamp_str(ts),qname,"base64-like")); break
        if suspicious_q: dns_events.append(("suspicious_qnames",src,suspicious_q[:10]))
    return dns_events, dns_csv

def detect_icmp_flood(packets):
    icmp_windows=defaultdict(lambda: deque()); icmp_csv=[]; icmp_events=[]
    for pkt in packets:
        if pkt.haslayer(ICMP) and pkt.haslayer(IP):
            icmp = pkt[ICMP]; ip=pkt[IP]; ts=float(pkt.time)
            if int(icmp.type)==8:
                icmp_windows[ip.src].append(ts); icmp_csv.append((timestamp_str(ts),ip.src,ip.dst))
                while icmp_windows[ip.src] and (ts-icmp_windows[ip.src][0])>ICMP_WINDOW: icmp_windows[ip.src].popleft()
                if len(icmp_windows[ip.src])>=ICMP_FLOOD_THRESHOLD:
                    icmp_events.append((ip.src,timestamp_str(icmp_windows[ip.src][0]),timestamp_str(icmp_windows[ip.src][-1]),len(icmp_windows[ip.src])))
                    icmp_windows[ip.src].clear()
    return icmp_events, icmp_csv

def detect_suspicious_hosts(packets):
    windows=defaultdict(lambda: deque()); unique_sets=defaultdict(set)
    suspect_events=[]; suspect_csv=[]
    for pkt in packets:
        if pkt.haslayer(IP):
            ip=pkt[IP]; ts=float(pkt.time); src=ip.src; dst=ip.dst
            windows[src].append((ts,dst)); unique_sets[src].add(dst)
            suspect_csv.append((timestamp_str(ts),src,dst))
            while windows[src] and (ts-windows[src][0][0])>SUSPICIOUS_HOSTS_WINDOW:
                _, olddst=windows[src].popleft()
                unique_sets[src]=set(d for (_,d) in windows[src])
            if len(unique_sets[src])>=SUSPICIOUS_HOSTS_UNIQUE_DST:
                suspect_events.append((src,timestamp_str(windows[src][0][0]),timestamp_str(windows[src][-1][0]),len(unique_sets[src])))
                windows[src].clear(); unique_sets[src].clear()
    return suspect_events, suspect_csv

# -----------------------------
# Extra Modules
# -----------------------------
def detect_http_keywords(packets):
    hits=[]
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            data=bytes(pkt[Raw].load).decode(errors='ignore').lower()
            for kw in HTTP_KEYWORDS:
                if kw in data:
                    hits.append((pkt[IP].src,pkt[IP].dst,kw))
    return hits

def compute_top_talkers(packets, top_n=5):
    volumes=defaultdict(int)
    for pkt in packets:
        if pkt.haslayer(IP):
            volumes[pkt[IP].src]+=len(pkt)
    top=sorted(volumes.items(),key=lambda x:x[1],reverse=True)[:top_n]
    total=sum(volumes.values()) or 1
    return [(ip,round(100*size/total,1)) for ip,size in top]

def protocol_distribution(packets):
    counter=Counter()
    for pkt in packets:
        if pkt.haslayer(TCP): counter["TCP"]+=1
        elif pkt.haslayer(UDP): counter["UDP"]+=1
        elif pkt.haslayer(ICMP): counter["ICMP"]+=1
        elif pkt.haslayer(ARP): counter["ARP"]+=1
        else: counter["OTHER"]+=1
    total=sum(counter.values()) or 1
    return {proto:f"{int(count*100/total)}%" for proto,count in counter.items()}

# -----------------------------
# Main
# -----------------------------
def main():
    ap=argparse.ArgumentParser(description="Advanced PCAP Threat Analyzer")
    ap.add_argument("--pcap", required=True, help="Input pcap file")
    ap.add_argument("--out", default="report.txt", help="Text report output file")
    ap.add_argument("--verbose", action="store_true", help="Verbose output")
    ap.add_argument("--module", choices=["core","http_keys","top_talkers","protocol_stats","all"], default="all")
    args=ap.parse_args()

    print("[*] Loading pcap:", args.pcap)
    packets = rdpcap(args.pcap)
    print("[*] Packets loaded:", len(packets))

    active_modules = [args.module] if args.module != "all" else ["core","http_keys","top_talkers","protocol_stats"]

    # ---------------- Core Modules ----------------
    if "core" in active_modules:
        print("[*] Running Core threat analysis...")
        arp_rows, arp_events = detect_arp(packets)
        portscan_events, portscan_csv = detect_port_scans(packets)
        syn_events, syn_csv = detect_syn_flood(packets)
        dns_events, dns_csv = detect_dns_anomalies(packets)
        icmp_events, icmp_csv = detect_icmp_flood(packets)
        suspect_events, suspect_csv = detect_suspicious_hosts(packets)

        write_csv("arp_map.csv", ["ip","macs"], arp_rows)
        write_csv("portscan.csv", ["time","src","dst","dstport"], portscan_csv)
        write_csv("syn_events.csv", ["time","src","dst","dstport"], syn_csv)
        write_csv("dns_events.csv", ["time","src","dst","qname","qtype"], dns_csv)
        write_csv("icmp_events.csv", ["time","src","dst"], icmp_csv)
        write_csv("suspicious_ips.csv", ["time","src","dst"], suspect_csv)

    # ---------------- Report Generation ----------------
    now = timestamp_str(time.time())
    with open(args.out,"w",encoding='utf-8') as rpt:
        rpt.write(f"Advanced PCAP Threat Analyzer Report\nGenerated: {now}\nSource PCAP: {args.pcap}\n\n")

        # Core
        if "core" in active_modules:
            rpt.write("== ARP Analysis ==\n")
            if arp_events:
                rpt.write("Potential ARP spoofing (IP mapped to multiple MACs):\n")
                for ip,macs in arp_events: rpt.write(f" - {ip} -> {', '.join(macs)}\n")
                rpt.write("See arp_map.csv for full mapping.\n\n")
            else: rpt.write("No ARP IP->multiple-MAC anomalies detected.\n\n")

            rpt.write("== Port Scan Analysis ==\n")
            if portscan_events:
                for ev in portscan_events:
                    src,s_ts,e_ts,count,sample = ev
                    rpt.write(f" - {src} scanned ~{count} unique ports between {s_ts} and {e_ts}. Sample: {sample}\n")
                rpt.write("\n")
            else: rpt.write("No port-scan-like patterns detected.\n\n")

            rpt.write("== SYN Flood Analysis ==\n")
            if syn_events:
                for ev in syn_events:
                    src,s_ts,e_ts,syn_count,synack_ratio = ev
                    rpt.write(f" - {src} sent {syn_count} SYNs between {s_ts} and {e_ts}. SYN-ACK ratio approx {synack_ratio}\n")
                rpt.write("\n")
            else: rpt.write("No SYN-flood-like patterns detected.\n\n")

            rpt.write("== DNS Analysis ==\n")
            if dns_events:
                for ev in dns_events:
                    if ev[0]=="high_rate": _,src,num,ts,sample=ev
                    elif ev[0]=="suspicious_qnames": _,src,sq=ev
                rpt.write("\n")
            else: rpt.write("No DNS anomalies detected.\n\n")

            rpt.write("== ICMP Analysis ==\n")
            if icmp_events:
                for ev in icmp_events:
                    src,s_ts,e_ts,count = ev
                    rpt.write(f" - ICMP flood suspected from {src}: {count} echo-requests between {s_ts} and {e_ts}\n")
                rpt.write("\n")
            else: rpt.write("No ICMP flood detected.\n\n")

            rpt.write("== Suspicious Hosts ==\n")
            if suspect_events:
                for ev in suspect_events:
                    src,s_ts,e_ts,uniq = ev
                    rpt.write(f" - {src} contacted {uniq} unique destinations between {s_ts} and {e_ts}\n")
                rpt.write("\n")
            else: rpt.write("No hosts contacting unusually many destinations detected.\n\n")

        # HTTP Keywords
        if "http_keys" in active_modules:
            rpt.write("== HTTP Keyword Detection ==\n")
            hits = detect_http_keywords(packets)
            if hits:
                for src,dst,kw in hits[:20]: rpt.write(f" - {src} -> {dst}: {kw}\n")
            else: rpt.write("No HTTP keywords detected.\n\n")

        # Top Talkers
        if "top_talkers" in active_modules:
            rpt.write("== Top Talkers ==\n")
            top = compute_top_talkers(packets)
            for ip,pct in top: rpt.write(f" - {ip} ~ {pct}% of traffic\n")
            rpt.write("\n")

        # Protocol Stats
        if "protocol_stats" in active_modules:
            rpt.write("== Protocol Distribution ==\n")
            dist = protocol_distribution(packets)
            for proto,pct in dist.items(): rpt.write(f" - {proto}: {pct}\n")
            rpt.write("\n")

    print(f"[+] Report written to {args.out}")
    print("[+] Done.")

if __name__ == "__main__":
    main()
