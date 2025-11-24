# Advanced PCAP Threat Analyzer

An advanced Python-based network traffic analyzer that detects potential threats in PCAP files. The tool is modular, allowing detection of ARP spoofing, port scans, SYN floods, ICMP floods, suspicious DNS queries, HTTP keywords, and more.

## Features

- **ARP Analysis:** Detect IP addresses mapped to multiple MAC addresses (possible ARP spoofing).  
- **Port Scan Detection:** Identify hosts scanning multiple ports within a short time window.  
- **SYN Flood Detection:** Detect hosts sending high volumes of SYN packets (possible DoS attack).  
- **DNS Anomaly Detection:** Identify suspicious DNS queries including long or base64-like domain names.  
- **ICMP Flood Detection:** Detect hosts sending excessive ICMP echo requests.  
- **Suspicious Host Detection:** Track hosts contacting unusually many unique destinations.  
- **HTTP Keyword Detection:** Scan TCP payloads for sensitive keywords (password, token, admin, etc.).  
- **Top Talkers & Protocol Stats:** Identify hosts generating the most traffic and protocol distribution.  

## Installation

1. Clone the repository:

```bash
git clone https://github.com/YourUsername/Advanced-PCAP-Threat-Analyzer.git
cd Advanced-PCAP-Threat-Analyzer
````

2. Install Python dependencies:

```bash
pip install scapy
```

3. Make sure you have Python 3.12+ installed.

## Usage

```bash
python main.py --pcap sample.pcap --out report.txt --module all
```

* `--pcap` : Input PCAP file
* `--out` : Output text report (default `report.txt`)
* `--module` : Select module (`core`, `http_keys`, `top_talkers`, `protocol_stats`, `all`)
* `--verbose` : Optional verbose output

Reports and CSV logs are saved in the `report/` directory.

## Example Output

* `report.txt` — Summary report
* `arp_map.csv`, `portscan.csv`, `syn_events.csv`, `dns_events.csv`, `icmp_events.csv`, `suspicious_ips.csv` — Detailed CSV logs

## Project Structure

```
Advanced-PCAP-Threat-Analyzer/
│
├─ main.py           # Main script
├─ Report/           # Output reports and CSV files
├─ README.md
└─ sample.pcap       # Optional sample PCAP for testing
```

## License

MIT License – feel free to use and modify for educational or research purposes.

## Author

github.com/lucixsherry06

