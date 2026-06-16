"""
Export packet-level features from PCAP/PCAPNG into CSV.

Beginner-friendly workflow:
1. Capture traffic with Wireshark.
2. Save the file into `data/raw/`.
3. Run this script to export selected fields with `tshark`.
4. Optionally anonymize IP addresses before sharing the CSV.

Example:
    python src/feature_extraction.py ^
        --input data/raw/youtube_traffic.pcapng ^
        --output data/processed/youtube_traffic.csv ^
        --label YouTube ^
        --display-filter "ip.addr == 10.100.1.194" ^
        --anonymize

Batch example:
    python src/feature_extraction.py ^
        --input-dir data/raw ^
        --output-dir data/processed ^
        --anonymize
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
        description="Export packet features from a PCAP/PCAPNG file into CSV."
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

    if single_file_mode and batch_mode:
        raise ValueError(
            "Use either single-file mode (--input/--output/--label) or batch mode "
            "(--input-dir/--output-dir), not both."
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

    raise ValueError(
        "Provide either --input/--output/--label for one file or "
        "--input-dir/--output-dir for batch export."
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
