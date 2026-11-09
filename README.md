#Hamad Mustafa

# Basic Network Sniffer (Python)

A simple network packet sniffer built with Python's standard library (raw sockets).
It captures live traffic and decodes packet headers so you can see how data flows on a network.

## Features
- Decodes Ethernet (Linux), IPv4, TCP, UDP and ICMP headers
- Shows source/destination IP, ports, service names (HTTP, DNS, SSH...), TCP flags, TTL
- Payload preview in ASCII and HEX, detects HTTP request lines
- Filters by protocol (`tcp`, `udp`, `icmp`) and by port
- Packet count limit, save output to a log file
- Capture summary with packet counts per protocol

## Requirements
- Python 3.8+
- No external libraries
- Administrator (Windows) or root (Linux) privileges

## Usage
```bash
# Windows (run terminal as Administrator)
python network_sniffer.py
python network_sniffer.py -p tcp -c 50
python network_sniffer.py --port 80
python network_sniffer.py -o capture.log

# Linux
sudo python3 network_sniffer.py -p udp -c 20
```

| Option | Description |
|---|---|
| `-c, --count` | Number of packets to capture (0 = unlimited) |
| `-p, --protocol` | Filter: `tcp`, `udp`, `icmp` |
| `--port` | Filter by source/destination port |
| `-o, --output` | Save output to a file |
| `-i, --interface-ip` | (Windows) IP of the adapter to sniff |
| `--no-payload` | Hide payload data |

## How it works
1. Opens a raw socket (`AF_PACKET` on Linux, `SOCK_RAW` + `SIO_RCVALL` on Windows).
2. Receives raw bytes and unpacks headers with `struct`.
3. Layers are parsed in order: Ethernet -> IPv4 -> TCP/UDP/ICMP -> payload.
4. Prints readable output and a final summary.

## Sample output
```
Packet #96  [18:48:24]  TCP
  IPv4     : 192.168.1.171 -> 192.168.1.1  TTL=128  Len=40  ID=35122
  TCP      : 24584 -> 80 (HTTP)  Flags=[ACK]
             Seq=3548637440  Ack=865965502  Win=254
```

## Disclaimer
For educational purposes only. Capture traffic only on networks you own or have permission to monitor.
