"""
Beginner-friendly traffic signature export pipeline.

This script reads three known PCAP files with tshark, applies traffic-specific
display filters, exports one CSV per traffic type, and then combines all CSV
files into one dataset for later machine learning experiments.

Output folder:
    traffic_signature_analysis/

Generated files:
    - youtube_signature.csv
    - browsing_signature.csv
    - download_signature.csv
    - traffic_signatures_combined.csv
"""

from __future__ import annotations

import subprocess
from pathlib import Path
import shutil

import pandas as pd


# These are the exact packet fields that will be exported from tshark.
# They are simple, interpretable features that are useful in beginner ML work.
EXPORT_FIELDS = [
    "frame.time_relative",
    "ip.src",
    "ip.dst",
    "ip.proto",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "frame.len",
    "dns.qry.name",
    "tls.handshake.extensions_server_name",
    "_ws.col.Protocol",
]


# Each traffic profile has:
# - a source PCAP file
# - a beginner-friendly label
# - a display filter that keeps the packets most relevant to that traffic type
# The filter comments explain why those packets matter for network analysis and ML.
TRAFFIC_PROFILES = [
    {
        "name": "youtube",
        "label": "youtube",
        "pcap_path": Path("data/raw/youtube_traffic.pcapng"),
        "output_csv": "youtube_signature.csv",
        # YouTube often uses DNS for name resolution and QUIC/UDP 443 for media delivery.
        # These patterns are useful because streaming traffic usually looks different
        # from browsing or file downloads.
        "display_filter": "ip.addr == 10.100.1.194 && (dns || quic || udp.port == 443)",
    },
    {
        "name": "browsing",
        "label": "browsing",
        "pcap_path": Path("data/raw/browsing_traffic.pcapng"),
        "output_csv": "browsing_signature.csv",
        # Browsing often includes DNS lookups, TCP transport, and TLS-protected web traffic.
        # These features help show short web sessions, multiple sites, and many destinations.
        "display_filter": "ip.addr == 10.100.1.194 && (dns || tcp || tls)",
    },
    {
        "name": "download",
        "label": "download",
        "pcap_path": Path("data/raw/download_traffic_1gb.pcapng"),
        "output_csv": "download_signature.csv",
        # Large downloads are commonly dominated by TCP and TLS traffic.
        # This helps isolate long, steady transfer behavior that often differs from streaming.
        "display_filter": "ip.addr == 10.100.1.89 && (tcp || tls)",
    },
]


def resolve_tshark_path() -> str:
    """Return a working tshark path or raise a clear error."""
    tshark_path = shutil.which("tshark")
    if tshark_path is not None:
        return tshark_path

    default_windows_path = Path("C:/Program Files/Wireshark/tshark.exe")
    if default_windows_path.exists():
        return str(default_windows_path)

    raise FileNotFoundError(
        "tshark was not found. Install Wireshark/TShark or add tshark to PATH."
    )


def ensure_pcap_exists(pcap_path: Path) -> None:
    """Fail early if a required PCAP file is missing."""
    if not pcap_path.exists():
        raise FileNotFoundError(f"Missing PCAP file: {pcap_path}")


def build_tshark_command(
    tshark_path: str, pcap_path: Path, display_filter: str
) -> list[str]:
    """Build a tshark command that exports selected fields as CSV text."""
    command = [
        tshark_path,
        "-r",
        str(pcap_path),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=,",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]

    for field in EXPORT_FIELDS:
        command.extend(["-e", field])

    return command


def export_profile_to_csv(
    tshark_path: str, profile: dict[str, object], output_dir: Path
) -> pd.DataFrame:
    """Run tshark for one traffic type, then add the label column in pandas."""
    pcap_path = Path(profile["pcap_path"])
    output_path = output_dir / str(profile["output_csv"])
    display_filter = str(profile["display_filter"])
    label = str(profile["label"])

    ensure_pcap_exists(pcap_path)
    command = build_tshark_command(tshark_path, pcap_path, display_filter)

    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"tshark export failed for {pcap_path.name}: "
            f"{result.stderr.strip() or 'unknown tshark error'}"
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path.write_text(result.stdout, encoding="utf-8", newline="")

    dataframe = pd.read_csv(output_path, keep_default_na=False)
    dataframe.columns = [column.strip() for column in dataframe.columns]
    dataframe = dataframe.fillna("")
    dataframe["label"] = label
    dataframe.to_csv(output_path, index=False)

    print(f"Created {output_path}")
    print(f"  label: {label}")
    print(f"  rows: {len(dataframe)}")
    print(f"  filter: {display_filter}")

    return dataframe


def combine_exports(dataframes: list[pd.DataFrame], output_dir: Path) -> Path:
    """Merge all per-traffic CSV exports into one combined dataset."""
    combined_path = output_dir / "traffic_signatures_combined.csv"
    combined_df = pd.concat(dataframes, ignore_index=True)
    combined_df.to_csv(combined_path, index=False)
    return combined_path


def main() -> None:
    output_dir = Path("traffic_signature_analysis")
    tshark_path = resolve_tshark_path()

    exported_frames: list[pd.DataFrame] = []
    for profile in TRAFFIC_PROFILES:
        exported_frames.append(
            export_profile_to_csv(
                tshark_path=tshark_path,
                profile=profile,
                output_dir=output_dir,
            )
        )

    combined_path = combine_exports(exported_frames, output_dir)
    print(f"Created {combined_path}")
    print(f"Total rows: {sum(len(frame) for frame in exported_frames)}")


if __name__ == "__main__":
    main()
