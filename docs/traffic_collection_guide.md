# Beginner Guide: Collecting Labeled Network Traffic with Wireshark

This guide explains how to collect simple labeled traffic for an AI-based network traffic classification project.

Goal:

- capture `YouTube` traffic
- capture `Download` traffic
- capture `Browsing` traffic
- save each traffic type as a separate labeled `PCAP` file

---

## 1. What Is a PCAP File?

A `PCAP` or `PCAPNG` file is a packet capture file.

It stores recorded network packets such as:

- source IP
- destination IP
- source port
- destination port
- protocol
- packet size
- timing information

You can think of it as a recording of network activity.

---

## 2. What Wireshark Does

Wireshark is a packet capture and analysis tool.

It helps you:

- capture live traffic from your network interface
- inspect packets one by one
- filter traffic by IP, protocol, or port
- export captures for later analysis

For this project, Wireshark is used only to collect and inspect traffic offline.

---

## 3. Safe and Ethical Data Collection Rules

Follow these rules every time:

- Capture only your own traffic or traffic you are explicitly allowed to analyze.
- Do not capture other people's traffic on shared networks without permission.
- Avoid logging passwords, private messages, banking activity, or sensitive personal data.
- Prefer collecting traffic on your own device and your own test network.
- Keep raw `pcap` files private whenever possible.
- Do not upload raw captures to a public GitHub repository.
- If you share derived CSV files, anonymize IP addresses first.
- Stop a capture when you have enough data; do not collect unnecessary traffic.

Good practice:

- use a private GitHub repo for raw experiments
- commit code and documentation publicly
- keep raw captures outside public version control

---

## 4. Basic Network Concepts to Notice

While collecting traffic, pay attention to:

- `source IP`: where a packet comes from
- `destination IP`: where a packet goes
- `source port`: sender-side application port
- `destination port`: receiver-side application port
- `protocol`: such as TCP, UDP, DNS, TLS, QUIC

These fields later become useful machine learning features.

---

## 5. Before You Start Capturing

Prepare a clean session:

1. Close apps you do not want in the capture.
2. Keep only the target activity active.
3. Choose the correct Wireshark interface, usually your active Wi-Fi or Ethernet adapter.
4. Start with short captures, around 1 to 5 minutes.
5. Record what you are doing so you can label files correctly.

Example notes:

- `12:10 - started YouTube video`
- `12:14 - stopped video`
- `12:20 - started browser search session`

---

## 6. How To Collect YouTube Traffic

Suggested action:

- open one or two YouTube videos
- watch them for a short period
- avoid browsing other sites during the capture

Expected traffic patterns:

- often `QUIC`
- often `UDP`
- some `DNS`
- continuous or bursty streaming traffic

Suggested capture file name:

- `youtube_traffic_01.pcapng`

Label:

- `YouTube`

---

## 7. How To Collect Download Traffic

Suggested action:

- download a large test file that you are allowed to download
- avoid background browsing during the capture

Expected traffic patterns:

- often `TCP`
- often `TLS`
- long-lived flows
- high bandwidth usage

Suggested capture file name:

- `download_traffic_1gb_01.pcapng`

Label:

- `Download`

Use safe sources for downloads, such as test files or public datasets you are allowed to access.

---

## 8. How To Collect Browsing Traffic

Suggested action:

- open several normal web pages
- perform searches
- move between multiple sites

Expected traffic patterns:

- `DNS`
- `TCP`
- `TLS`
- many short connections
- multiple destination IPs and domains

Suggested capture file name:

- `browsing_traffic_01.pcapng`

Label:

- `Browsing`

---

## 9. Suggested File Naming Rules

Use simple and consistent file names.

Recommended format:

```text
<label>_traffic_<session>.pcapng
```

Examples:

- `youtube_traffic_01.pcapng`
- `youtube_traffic_02.pcapng`
- `browsing_traffic_01.pcapng`
- `download_traffic_1gb_01.pcapng`

If you want more detail:

```text
<label>_traffic_<device>_<session>.pcapng
```

Examples:

- `youtube_traffic_laptop_01.pcapng`
- `browsing_traffic_phone_01.pcapng`

Rules:

- use lowercase
- use underscores
- keep labels consistent
- do not use random names like `test1.pcapng`

---

## 10. Simple Labeling Logic

Each capture should represent one main traffic class.

Examples:

- YouTube session -> `YouTube`
- large file download -> `Download`
- general web session -> `Browsing`

Why this matters:

- machine learning needs clear labels
- mixed captures are harder to learn from
- good labeling improves dataset quality

Try to avoid mixing multiple traffic types in one file.

---

## 11. Recommended Capture Workflow

For each class:

1. Start Wireshark capture.
2. Perform only the target activity.
3. Stop the capture after enough packets are collected.
4. Save the file with a clear name.
5. Write down the label in your notes.

Example workflow:

1. Start capture
2. Watch YouTube for 3 minutes
3. Stop capture
4. Save as `youtube_traffic_01.pcapng`
5. Record label as `YouTube`

Repeat the same process for `Download` and `Browsing`.

---

## 12. What You Learn At The End Of This Step

By the end of this step, you should understand:

- what a `PCAP` file is
- how Wireshark capture works
- the meaning of source IP and destination IP
- how traffic labeling works
- basic ethical rules for collecting packet data

---

## 13. Next Step: Day 3

After collecting labeled `pcapng` files, the next step is to convert them into table data.

Target beginner features:

- `src_ip`
- `dst_ip`
- `src_port`
- `dst_port`
- `protocol`
- `packet_length`
- `time_delta`
- `label`

Pipeline idea:

```text
PCAP/PCAPNG -> tshark/Wireshark export -> CSV -> Python dataset preparation
```

Suggested Day 3 goal:

- combine multiple exported CSV files into one labeled dataset for machine learning
