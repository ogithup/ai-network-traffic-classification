# Day 2 Analysis

This document is for manual Wireshark analysis before feature engineering.

How to use it:

1. Open each PCAP file in Wireshark.
2. Apply the filters listed below.
3. Check `Protocol Hierarchy`, `Conversations`, `Endpoints`, and `I/O Graph`.
4. Fill in the observations section.

---

## YouTube

PCAP file:

- `youtube_traffic.pcapng`

Suggested filters:

- `ip.addr == 10.100.1.194`
- `quic`
- `udp`
- `dns`

Expected protocols:

- QUIC
- UDP
- DNS

What to check:

- Top protocol
- Whether QUIC is present
- DNS query count
- Most common destination IP
- Whether traffic looks continuous over time

Observations:

- Top protocol:
- QUIC present:
- DNS query count:
- Most common destination IP:
- Continuous traffic:
- Notes:

Possible ML features later:

- UDP ratio
- QUIC presence
- DNS query count
- Average packet length
- Destination IP count
- Total packets

---

## Download

PCAP file:

- `download_traffic_1gb.pcapng`

Suggested filters:

- `ip.addr == 10.100.1.89`
- `tcp`
- `dns`
- `tls`

Expected protocols:

- TCP
- TLS
- DNS

What to check:

- Whether TCP is dominant
- Whether traffic mostly talks to one destination IP
- Whether traffic is continuous during the download
- Whether flows are long-lived

Observations:

- TCP dominant:
- Single main destination IP:
- Continuous traffic:
- Long TCP flows:
- Notes:

Possible ML features later:

- TCP ratio
- Average flow duration
- Destination concentration
- Total bytes
- Packet count
- Throughput over time

---

## Browsing

PCAP file:

- `browsing_traffic.pcapng`

Suggested filters:

- `ip.addr == 10.100.1.194`
- `dns`
- `tcp`
- `tls`

Expected protocols:

- DNS
- TCP
- TLS

What to check:

- How many different sites were opened
- How many different destination IPs appear
- Whether DNS activity is dense
- Whether connections are mostly short

Observations:

- Different sites opened:
- Different destination IPs:
- DNS intensive:
- Many short connections:
- Notes:

Possible ML features later:

- DNS query count
- Unique domain count
- Unique destination IP count
- Short flow count
- Average packet length
- Flow duration statistics

---

## Cross-Traffic Comparison

Use this section after analyzing all PCAP files.

| Traffic Type | Main Protocols | Connection Style | DNS Intensity | Destination Diversity | Notes |
| --- | --- | --- | --- | --- | --- |
| YouTube |  |  |  |  |  |
| Download |  |  |  |  |  |
| Browsing |  |  |  |  |  |

---

## Day 2 Summary

Write a short summary in your own words:

- What was the clearest difference between YouTube, Download, and Browsing?
- Which protocol appeared most often in each traffic type?
- Which features seem useful for machine learning?
- What did you learn about network traffic behavior today?
