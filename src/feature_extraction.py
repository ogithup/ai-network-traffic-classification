"""
Beginner-friendly feature extraction pipeline.

This file supports two learning stages:

1. PCAP/PCAPNG -> CSV export with tshark
2. Multiple exported CSV files -> one clean machine-learning dataset

Why both modes exist:
- Day 2 focused on understanding packet captures and protocol signatures.
- Day 3 focuses on turning packet exports into a simple table for ML.

Example 1: export one PCAP file into CSV
    python src/feature_extraction.py ^
        --input data/raw/youtube_traffic.pcapng ^
        --output data/processed/youtube_traffic.csv ^
        --label YouTube ^
        --display-filter "ip.addr == 10.100.1.194" ^
        --anonymize

Example 2: export all PCAP files from one folder
    python src/feature_extraction.py ^
        --input-dir data/raw ^
        --output-dir data/processed ^
        --anonymize

Example 3: combine exported CSV files into one ML-ready dataset
    python src/feature_extraction.py ^
        --combine-input-dir traffic_signature_analysis ^
        --combine-output data/processed/final_labeled_dataset.csv
"""

from __future__ import annotations

import argparse
import csv
import shutil
import subprocess
from pathlib import Path

import pandas as pd


LABEL_OVERRIDES = {
    "youtube": "YouTube",
    "netflix": "Netflix",
    "voip": "VoIP",
}

TSHARK_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "eth.type",
    "ip.src",
    "ip.dst",
    "ip.proto",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "_ws.col.Protocol",
    "dns.qry.name",
    "tls.handshake.extensions_server_name",
]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Export packet features or combine exported CSV files into one ML dataset."
    )
    parser.add_argument("--input", help="Path to the input PCAP/PCAPNG.")
    parser.add_argument("--output", help="Path to the output CSV file.")
    parser.add_argument(
        "--input-dir",
        help="Directory that contains .pcap or .pcapng files for batch export.",
    )
    parser.add_argument(
        "--output-dir",
        help="Directory where batch CSV exports will be written.",
    )
    parser.add_argument(
        "--label",
        help="Traffic label to add to the exported rows. Example: YouTube or Browsing.",
    )
    parser.add_argument(
        "--display-filter",
        default="",
        help='Optional Wireshark display filter. Example: "ip.addr == 10.100.1.194".',
    )
    parser.add_argument(
        "--anonymize",
        action="store_true",
        help="Replace IP addresses with stable placeholders before saving.",
    )
    parser.add_argument(
        "--combine-input-dir",
        help="Directory that contains exported CSV files to combine into one dataset.",
    )
    parser.add_argument(
        "--combine-output",
        help="Path to the final combined dataset CSV.",
    )
    return parser


def resolve_tshark_path() -> str:
    tshark_path = shutil.which("tshark")
    if tshark_path is not None:
        return tshark_path

    default_windows_path = Path("C:/Program Files/Wireshark/tshark.exe")
    if default_windows_path.exists():
        return str(default_windows_path)

    raise FileNotFoundError(
        "tshark was not found in PATH. Install Wireshark/TShark first."
    )


def validate_args(args: argparse.Namespace) -> None:
    single_file_mode = bool(args.input or args.output or args.label)
    batch_mode = bool(args.input_dir or args.output_dir)
    combine_mode = bool(args.combine_input_dir or args.combine_output)

    if sum([single_file_mode, batch_mode, combine_mode]) > 1:
        raise ValueError(
            "Use only one mode at a time: single-file export, batch export, or CSV combine mode."
        )

    if single_file_mode:
        if not (args.input and args.output and args.label):
            raise ValueError(
                "Single-file mode requires --input, --output, and --label."
            )
        return

    if batch_mode:
        if not (args.input_dir and args.output_dir):
            raise ValueError("Batch mode requires --input-dir and --output-dir.")
        return

    if combine_mode:
        if not (args.combine_input_dir and args.combine_output):
            raise ValueError(
                "CSV combine mode requires --combine-input-dir and --combine-output."
            )
        return

    raise ValueError(
        "Provide one mode: --input/--output/--label, "
        "--input-dir/--output-dir, or --combine-input-dir/--combine-output."
    )


def normalize_label(raw_label: str) -> str:
    label_key = raw_label.strip().lower()
    if label_key in LABEL_OVERRIDES:
        return LABEL_OVERRIDES[label_key]

    return raw_label.strip().replace("-", " ").replace("_", " ").title()


def infer_label_from_filename(input_path: Path) -> str:
    stem = input_path.stem.lower()
    noise_tokens = {"traffic", "capture", "pcap", "pcapng", "raw"}
    parts = [
        part
        for part in stem.replace("-", "_").split("_")
        if part and part not in noise_tokens
    ]

    if not parts:
        raise FileNotFoundError(
            f"Could not infer a label from filename: {input_path.name}"
        )

    return normalize_label(" ".join(parts))


def export_with_tshark(
    tshark_path: str, input_path: Path, output_path: Path, display_filter: str
) -> None:
    command = [
        tshark_path,
        "-r",
        str(input_path),
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

    if display_filter:
        command.extend(["-Y", display_filter])

    for field in TSHARK_FIELDS:
        command.extend(["-e", field])

    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "tshark export failed.")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(result.stdout, encoding="utf-8", newline="")


def anonymize_ips(dataframe: pd.DataFrame) -> pd.DataFrame:
    df = dataframe.copy()
    ip_columns = [column for column in ("ip.src", "ip.dst") if column in df.columns]
    unique_ips: list[str] = []

    for column in ip_columns:
        unique_ips.extend(
            value for value in df[column].dropna().astype(str).unique() if value.strip()
        )

    mapping = {
        ip: f"host_{index:03d}"
        for index, ip in enumerate(sorted(set(unique_ips)), start=1)
    }

    for column in ip_columns:
        df[column] = df[column].astype(str).map(lambda value: mapping.get(value, value))

    return df


def clean_exported_csv(output_path: Path, label: str, anonymize: bool) -> pd.DataFrame:
    df = pd.read_csv(output_path, keep_default_na=False, quoting=csv.QUOTE_MINIMAL)
    df.columns = [column.strip() for column in df.columns]
    df = df.fillna("")
    df["label"] = label

    if anonymize:
        df = anonymize_ips(df)

    df.to_csv(output_path, index=False)
    return df


def export_single_file(
    tshark_path: str,
    input_path: Path,
    output_path: Path,
    label: str,
    display_filter: str,
    anonymize: bool,
) -> pd.DataFrame:
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    export_with_tshark(
        tshark_path=tshark_path,
        input_path=input_path,
        output_path=output_path,
        display_filter=display_filter,
    )
    return clean_exported_csv(
        output_path=output_path,
        label=label,
        anonymize=anonymize,
    )


def find_capture_files(input_dir: Path) -> list[Path]:
    captures = sorted(input_dir.glob("*.pcap")) + sorted(input_dir.glob("*.pcapng"))
    return sorted(set(captures))


def find_exported_csv_files(input_dir: Path) -> list[Path]:
    """Find exported CSV files that will be turned into one ML dataset."""
    return sorted(
        path
        for path in input_dir.glob("*.csv")
        if path.is_file() and path.name != "traffic_signatures_combined.csv"
    )


def find_column_name(dataframe: pd.DataFrame, expected_name: str) -> str:
    """Resolve a CSV column name with a case-insensitive lookup."""
    expected_key = expected_name.strip().lower()
    for column_name in dataframe.columns:
        if column_name.strip().lower() == expected_key:
            return column_name
    raise KeyError(f"Column not found: {expected_name}")


def standardize_protocol(dataframe: pd.DataFrame) -> pd.Series:
    """
    Create one beginner-friendly `protocol` column.

    We prefer easy-to-read labels instead of raw tshark values.
    The priority order matters:
    - DNS is easy to spot from query names or protocol text
    - QUIC should stay visible because it is important for YouTube-like traffic
    - TLS should stay visible because it is important for encrypted web/download traffic
    - otherwise we fall back to TCP / UDP using the IP protocol number
    """
    protocol_text = dataframe[find_column_name(dataframe, "_ws.col.Protocol")].astype(str).str.upper()
    dns_name = dataframe[find_column_name(dataframe, "dns.qry.name")].astype(str).str.strip()
    ip_proto = pd.to_numeric(
        dataframe[find_column_name(dataframe, "ip.proto")], errors="coerce"
    ).fillna(0)

    protocol = pd.Series("OTHER", index=dataframe.index, dtype="object")
    protocol.loc[ip_proto == 6] = "TCP"
    protocol.loc[ip_proto == 17] = "UDP"
    protocol.loc[protocol_text.str.contains("TLS", na=False)] = "TLS"
    protocol.loc[protocol_text.str.contains("QUIC", na=False)] = "QUIC"
    protocol.loc[(dns_name != "") | protocol_text.str.contains("DNS", na=False)] = "DNS"
    return protocol


def coalesce_ports(dataframe: pd.DataFrame, source_column: str, fallback_column: str) -> pd.Series:
    """
    Merge TCP and UDP port columns into one generic port column.

    Why this is needed:
    - some packets are TCP, so only the TCP port columns are filled
    - some packets are UDP, so only the UDP port columns are filled
    - ML models usually work better with one clean `src_port` and `dst_port` column
    """
    first = dataframe[find_column_name(dataframe, source_column)].astype(str).str.strip()
    second = dataframe[find_column_name(dataframe, fallback_column)].astype(str).str.strip()
    merged = first.where(first != "", second)
    merged = merged.where(merged != "", "0")
    return pd.to_numeric(merged, errors="coerce").fillna(0).astype(int)


def calculate_time_delta(dataframe: pd.DataFrame) -> pd.Series:
    """
    Build `time_delta` from packet timestamps.

    We use `frame.time_relative` if it exists because it already represents time
    relative to the start of the capture. The first packet gets `0.0`.
    Each next packet gets the time gap from the previous packet.
    """
    if "frame.time_relative" in dataframe.columns:
        relative_time = pd.to_numeric(
            dataframe[find_column_name(dataframe, "frame.time_relative")], errors="coerce"
        ).fillna(0.0)
        return relative_time.diff().fillna(0.0).clip(lower=0.0)

    if "frame.time_epoch" in dataframe.columns:
        epoch_time = pd.to_numeric(
            dataframe[find_column_name(dataframe, "frame.time_epoch")], errors="coerce"
        ).fillna(0.0)
        return epoch_time.diff().fillna(0.0).clip(lower=0.0)

    return pd.Series(0.0, index=dataframe.index)


def standardize_exported_csv(dataframe: pd.DataFrame) -> pd.DataFrame:
    """
    Convert one exported tshark CSV into the exact Day 3 beginner feature format.

    Output columns:
    - src_ip
    - dst_ip
    - src_port
    - dst_port
    - protocol
    - packet_length
    - time_delta
    - label
    """
    df = dataframe.copy()
    df.columns = [column.strip() for column in df.columns]
    df = df.fillna("")

    standardized = pd.DataFrame(
        {
            "src_ip": df[find_column_name(df, "ip.src")].astype(str).str.strip(),
            "dst_ip": df[find_column_name(df, "ip.dst")].astype(str).str.strip(),
            "src_port": coalesce_ports(df, "tcp.srcport", "udp.srcport"),
            "dst_port": coalesce_ports(df, "tcp.dstport", "udp.dstport"),
            "protocol": standardize_protocol(df),
            "packet_length": pd.to_numeric(
                df[find_column_name(df, "frame.len")], errors="coerce"
            ).fillna(0).astype(int),
            "time_delta": calculate_time_delta(df),
            "label": df[find_column_name(df, "label")].astype(str).str.strip().str.lower(),
        }
    )

    return standardized


def combine_exported_csvs(input_dir: Path, output_path: Path) -> pd.DataFrame:
    """
    Read multiple tshark-exported CSV files and combine them into one clean dataset.

    This is the missing Day 3 step:
    - read many exported CSV files
    - standardize the column names
    - merge TCP and UDP ports into generic port features
    - simplify protocol names
    - calculate time_delta
    - combine all rows into one final CSV
    """
    if not input_dir.exists():
        raise FileNotFoundError(f"Combine input directory not found: {input_dir}")

    csv_files = find_exported_csv_files(input_dir)
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in: {input_dir}")

    standardized_frames: list[pd.DataFrame] = []
    for csv_file in csv_files:
        dataframe = pd.read_csv(csv_file, keep_default_na=False, low_memory=False)
        standardized = standardize_exported_csv(dataframe)
        standardized_frames.append(standardized)
        print(f"Read CSV: {csv_file}")
        print(f"  rows: {len(standardized)}")
        print(f"  labels found: {sorted(standardized['label'].unique())}")

    combined = pd.concat(standardized_frames, ignore_index=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    combined.to_csv(output_path, index=False)
    return combined


def export_directory(
    tshark_path: str,
    input_dir: Path,
    output_dir: Path,
    anonymize: bool,
) -> None:
    if not input_dir.exists():
        raise FileNotFoundError(f"Input directory not found: {input_dir}")

    capture_files = find_capture_files(input_dir)
    if not capture_files:
        raise FileNotFoundError(f"No .pcap or .pcapng files found in: {input_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)

    for capture_file in capture_files:
        label = infer_label_from_filename(capture_file)
        output_path = output_dir / f"{capture_file.stem}.csv"
        dataframe = export_single_file(
            tshark_path=tshark_path,
            input_path=capture_file,
            output_path=output_path,
            label=label,
            display_filter="",
            anonymize=anonymize,
        )
        print(f"Export complete: {output_path}")
        print(f"Rows: {len(dataframe)}")
        print(f"Columns: {len(dataframe.columns)}")
        print(f"Label: {label}")
        if anonymize:
            print("IP anonymization: enabled")


def main() -> None:
    args = build_parser().parse_args()
    validate_args(args)

    if args.combine_input_dir:
        combined = combine_exported_csvs(
            input_dir=Path(args.combine_input_dir),
            output_path=Path(args.combine_output),
        )
        print(f"Combined dataset created: {args.combine_output}")
        print(f"Rows: {len(combined)}")
        print(f"Columns: {list(combined.columns)}")
        print("Labels:", sorted(combined["label"].unique()))
        return

    tshark_path = resolve_tshark_path()

    if args.input_dir:
        export_directory(
            tshark_path=tshark_path,
            input_dir=Path(args.input_dir),
            output_dir=Path(args.output_dir),
            anonymize=args.anonymize,
        )
        return

    dataframe = export_single_file(
        tshark_path=tshark_path,
        input_path=Path(args.input),
        output_path=Path(args.output),
        label=normalize_label(args.label),
        display_filter=args.display_filter,
        anonymize=args.anonymize,
    )

    print(f"Export complete: {args.output}")
    print(f"Rows: {len(dataframe)}")
    print(f"Columns: {len(dataframe.columns)}")
    print(f"Label: {normalize_label(args.label)}")
    if args.anonymize:
        print("IP anonymization: enabled")


if __name__ == "__main__":
    main()
