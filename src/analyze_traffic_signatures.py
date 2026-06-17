"""
Analyze traffic signature CSV files with simple Python rules.

Why this script exists:
- Wireshark shows protocol hierarchy interactively.
- This script recreates a simplified version of those findings in Python.
- The goal is to help a student turn packet captures into measurable features.

Input files:
    traffic_signature_analysis/youtube_signature.csv
    traffic_signature_analysis/browsing_signature.csv
    traffic_signature_analysis/download_signature.csv

Output file:
    docs/day2_analysis_generated.md
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd


SIGNATURE_FILES = {
    "youtube": Path("traffic_signature_analysis/youtube_signature.csv"),
    "browsing": Path("traffic_signature_analysis/browsing_signature.csv"),
    "download": Path("traffic_signature_analysis/download_signature.csv"),
}


def find_column_name(dataframe: pd.DataFrame, expected_name: str) -> str:
    """Resolve a column name with a case-insensitive lookup."""
    expected_key = expected_name.strip().lower()
    for column_name in dataframe.columns:
        if column_name.strip().lower() == expected_key:
            return column_name
    raise KeyError(f"Column not found: {expected_name}")


def load_signature_csv(csv_path: Path | str) -> pd.DataFrame:
    """Load one signature CSV and keep blanks as empty strings."""
    csv_path = Path(csv_path)
    if not csv_path.exists():
        raise FileNotFoundError(f"Missing signature CSV: {csv_path}")

    dataframe = pd.read_csv(csv_path, keep_default_na=False, low_memory=False)
    dataframe.columns = [column.strip() for column in dataframe.columns]
    return dataframe.fillna("")


def numeric_series(dataframe: pd.DataFrame, column_name: str) -> pd.Series:
    """Convert a column to numeric values and replace invalid entries with 0."""
    resolved_name = find_column_name(dataframe, column_name)
    return pd.to_numeric(dataframe[resolved_name], errors="coerce").fillna(0)


def protocol_mask(dataframe: pd.DataFrame, protocol_name: str) -> pd.Series:
    """
    Build a simple boolean mask for one protocol family.

    The rules are intentionally easy to understand:
    - `ip.proto` values come from the packet data itself.
    - The meanings of those values are standardized: 6 = TCP, 17 = UDP.
    - TCP and UDP can be inferred from ip.proto or filled port columns.
    - DNS can be inferred from query names or protocol labels.
    - TLS can be inferred from TLS hostname fields or protocol labels.
    - QUIC is detected from the Wireshark protocol text.
    """
    protocol_column = find_column_name(dataframe, "_ws.col.Protocol")
    protocol_text = dataframe[protocol_column].astype(str).str.upper()
    ip_src = dataframe[find_column_name(dataframe, "ip.src")].astype(str).str.strip()
    ip_dst = dataframe[find_column_name(dataframe, "ip.dst")].astype(str).str.strip()
    ip_proto = numeric_series(dataframe, "ip.proto")
    tcp_src = dataframe[find_column_name(dataframe, "tcp.srcport")].astype(str).str.strip()
    tcp_dst = dataframe[find_column_name(dataframe, "tcp.dstport")].astype(str).str.strip()
    udp_src = dataframe[find_column_name(dataframe, "udp.srcport")].astype(str).str.strip()
    udp_dst = dataframe[find_column_name(dataframe, "udp.dstport")].astype(str).str.strip()
    dns_name = dataframe[find_column_name(dataframe, "dns.qry.name")].astype(str).str.strip()
    tls_name = dataframe[
        find_column_name(dataframe, "tls.handshake.extensions_server_name")
    ].astype(str).str.strip()

    if protocol_name == "tcp":
        return (ip_proto == 6) | (tcp_src != "") | (tcp_dst != "")
    if protocol_name == "udp":
        return (ip_proto == 17) | (udp_src != "") | (udp_dst != "")
    if protocol_name == "dns":
        return (dns_name != "") | protocol_text.str.contains("DNS", na=False)
    if protocol_name == "tls":
        # Many encrypted packets are shown as TCP after the TLS handshake phase.
        # To approximate Wireshark's TLS hierarchy better:
        # 1. mark explicit TLS packets
        # 2. mark TCP/443 packets
        # 3. if a TCP flow contains any TLS packet, treat the whole flow as TLS-associated
        tcp_443 = (tcp_src == "443") | (tcp_dst == "443")
        explicit_tls = (tls_name != "") | protocol_text.str.contains("TLS", na=False) | tcp_443

        flow_keys = (
            ip_src.where(ip_src <= ip_dst, ip_dst)
            + "|"
            + ip_dst.where(ip_src <= ip_dst, ip_src)
            + "|"
            + tcp_src.where(tcp_src <= tcp_dst, tcp_dst)
            + "|"
            + tcp_dst.where(tcp_src <= tcp_dst, tcp_src)
        )
        tcp_flow_mask = (ip_proto == 6) & ((tcp_src != "") | (tcp_dst != ""))
        tls_flow_keys = set(flow_keys[tcp_flow_mask & explicit_tls])
        flow_based_tls = tcp_flow_mask & flow_keys.isin(tls_flow_keys)

        return explicit_tls | flow_based_tls
    if protocol_name == "quic":
        return protocol_text.str.contains("QUIC", na=False)

    raise ValueError(f"Unsupported protocol name: {protocol_name}")


def protocol_stats(dataframe: pd.DataFrame, protocol_name: str) -> dict[str, float]:
    """Calculate packet and byte ratios for one protocol."""
    mask = protocol_mask(dataframe, protocol_name)
    total_packets = len(dataframe)
    total_bytes = numeric_series(dataframe, "frame.len").sum()
    packet_count = int(mask.sum())
    byte_count = int(numeric_series(dataframe.loc[mask], "frame.len").sum())

    packet_ratio = (packet_count / total_packets * 100) if total_packets else 0
    byte_ratio = (byte_count / total_bytes * 100) if total_bytes else 0

    return {
        "packet_count": packet_count,
        "packet_ratio": packet_ratio,
        "byte_count": byte_count,
        "byte_ratio": byte_ratio,
    }


def top_destination_ip(dataframe: pd.DataFrame) -> str:
    """Return the most common destination IP in the CSV."""
    destination_column = find_column_name(dataframe, "ip.dst")
    destination_counts = dataframe[destination_column].astype(str).str.strip()
    destination_counts = destination_counts[destination_counts != ""].value_counts()
    if destination_counts.empty:
        return "N/A"
    return str(destination_counts.index[0])


def unique_dns_queries(dataframe: pd.DataFrame) -> int:
    """Count unique DNS query names."""
    dns_column = find_column_name(dataframe, "dns.qry.name")
    dns_values = dataframe[dns_column].astype(str).str.strip()
    dns_values = dns_values[dns_values != ""]
    return int(dns_values.nunique())


def unique_destination_ips(dataframe: pd.DataFrame) -> int:
    """Count unique destination IP addresses."""
    destination_column = find_column_name(dataframe, "ip.dst")
    values = dataframe[destination_column].astype(str).str.strip()
    values = values[values != ""]
    return int(values.nunique())


def traffic_continuity_note(dataframe: pd.DataFrame) -> str:
    """
    Estimate whether traffic is continuous.

    The idea is simple:
    - Sort packets by relative time
    - Compute gaps between packets
    - If the largest gap is small, traffic looks continuous
    """
    time_values = numeric_series(dataframe, "frame.time_relative").sort_values()
    if len(time_values) < 2:
        return "Not enough packets to judge continuity."

    gaps = time_values.diff().fillna(0)
    max_gap = float(gaps.max())
    median_gap = float(gaps.median())

    if max_gap < 1:
        return f"Very continuous traffic. Max gap: {max_gap:.3f}s, median gap: {median_gap:.5f}s."
    if max_gap < 5:
        return f"Mostly continuous traffic. Max gap: {max_gap:.3f}s, median gap: {median_gap:.5f}s."
    return f"Burstier traffic with noticeable pauses. Max gap: {max_gap:.3f}s, median gap: {median_gap:.5f}s."


def classify_signature(
    metrics: dict[str, dict[str, float]],
    dns_query_count: int,
    unique_destination_count: int,
) -> str:
    """Turn protocol ratios into a short human-readable traffic signature."""
    quic_ratio = metrics["quic"]["packet_ratio"]
    udp_ratio = metrics["udp"]["packet_ratio"]
    tcp_ratio = metrics["tcp"]["packet_ratio"]
    tls_ratio = metrics["tls"]["byte_ratio"]
    dns_ratio = metrics["dns"]["packet_ratio"]

    if quic_ratio > 60 and udp_ratio > 60:
        return "Streaming-like signature: QUIC + UDP dominant."
    if tcp_ratio > 70 and dns_ratio > 1 and unique_destination_count > 20:
        return "Browsing-like signature: mostly TCP with visible DNS activity."
    if tcp_ratio > 90 and tls_ratio > 70 and quic_ratio < 5:
        return "Download-like signature: TCP + TLS dominant with almost no QUIC."
    if tcp_ratio > 70 and dns_query_count > 100:
        return "Browsing-like signature: mostly TCP with visible DNS activity."
    return "Mixed signature: no single dominant pattern."


def analyze_dataframe(label: str, dataframe: pd.DataFrame) -> dict[str, object]:
    """Analyze one traffic CSV and return summary statistics."""
    metrics = {
        protocol_name: protocol_stats(dataframe, protocol_name)
        for protocol_name in ("tcp", "udp", "dns", "tls", "quic")
    }

    protocol_counts = (
        dataframe[find_column_name(dataframe, "_ws.col.Protocol")]
        .astype(str)
        .str.strip()
        .replace("", "UNKNOWN")
        .value_counts()
        .head(5)
    )

    dns_packet_count = int(protocol_mask(dataframe, "dns").sum())
    unique_destinations = unique_destination_ips(dataframe)

    return {
        "label": label,
        "total_packets": len(dataframe),
        "total_bytes": int(numeric_series(dataframe, "frame.len").sum()),
        "metrics": metrics,
        "top_protocols": protocol_counts,
        "top_destination_ip": top_destination_ip(dataframe),
        "dns_query_count": dns_packet_count,
        "unique_dns_queries": unique_dns_queries(dataframe),
        "unique_destination_ips": unique_destinations,
        "continuity_note": traffic_continuity_note(dataframe),
        "signature_note": classify_signature(
            metrics=metrics,
            dns_query_count=dns_packet_count,
            unique_destination_count=unique_destinations,
        ),
    }


def write_markdown_report(results: list[dict[str, object]], output_path: Path) -> None:
    """Write a beginner-friendly Markdown report."""
    lines: list[str] = []
    lines.append("# Day 2 Analysis Generated by Python")
    lines.append("")
    lines.append("This report was generated from the exported signature CSV files.")
    lines.append("It approximates Wireshark protocol hierarchy findings with simple Python rules.")
    lines.append("")

    for result in results:
        metrics = result["metrics"]
        lines.append(f"## {str(result['label']).title()}")
        lines.append("")
        lines.append(f"- Total packets: `{result['total_packets']}`")
        lines.append(f"- Total bytes: `{result['total_bytes']}`")
        lines.append(f"- Top destination IP: `{result['top_destination_ip']}`")
        lines.append(f"- DNS packet count: `{result['dns_query_count']}`")
        lines.append(f"- Unique DNS queries: `{result['unique_dns_queries']}`")
        lines.append(f"- Unique destination IPs: `{result['unique_destination_ips']}`")
        lines.append("")
        lines.append("### Protocol Ratios")
        lines.append("")
        for protocol_name in ("tcp", "udp", "tls", "quic", "dns"):
            protocol_result = metrics[protocol_name]
            lines.append(
                f"- {protocol_name.upper()}: "
                f"{protocol_result['packet_ratio']:.1f}% packets, "
                f"{protocol_result['byte_ratio']:.1f}% bytes "
                f"({protocol_result['packet_count']} packets)"
            )
        lines.append("")
        lines.append("### Top Protocol Labels")
        lines.append("")
        for protocol_name, count in result["top_protocols"].items():
            lines.append(f"- {protocol_name}: {int(count)} packets")
        lines.append("")
        lines.append("### Interpretation")
        lines.append("")
        lines.append(f"- Signature: {result['signature_note']}")
        lines.append(f"- Continuity: {result['continuity_note']}")
        lines.append("")

    lines.append("## Initial Conclusion")
    lines.append("")
    lines.append("Each traffic type shows a different protocol distribution that can become ML features.")
    lines.append("")
    lines.append("- YouTube tends to favor QUIC and UDP.")
    lines.append("- Download tends to favor TCP and TLS.")
    lines.append("- Browsing tends to mix TCP, TLS, and more visible DNS activity.")
    lines.append("")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    results: list[dict[str, object]] = []

    for label, csv_path in SIGNATURE_FILES.items():
        dataframe = load_signature_csv(csv_path)
        results.append(analyze_dataframe(label, dataframe))

    output_path = Path("docs/day2_analysis_generated.md")
    write_markdown_report(results, output_path)

    print(f"Created {output_path}")
    for result in results:
        print(
            f"{result['label']}: "
            f"TCP {result['metrics']['tcp']['packet_ratio']:.1f}%, "
            f"UDP {result['metrics']['udp']['packet_ratio']:.1f}%, "
            f"TLS {result['metrics']['tls']['byte_ratio']:.1f}% bytes, "
            f"QUIC {result['metrics']['quic']['packet_ratio']:.1f}%"
        )


if __name__ == "__main__":
    main()
