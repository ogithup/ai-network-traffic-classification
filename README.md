# AI Network Traffic Classification

Beginner-friendly Python project for classifying network traffic from offline `PCAP` or exported `CSV` files.

## Project Goal

The first goal of this project is simple:

- Take captured network traffic
- Extract useful features from it
- Train a basic machine learning model
- Classify traffic into categories such as:
  - `YouTube`
  - `Netflix`
  - `Gaming`
  - `VoIP`
  - `Browsing`

This project starts with **offline classification**, not real-time detection.

## Project Structure

```text
ai-network-traffic-classification/
├── data/
│   ├── raw/
│   └── processed/
├── notebooks/
│   └── 01_exploration.ipynb
├── src/
│   ├── feature_extraction.py
│   ├── train_model.py
│   └── evaluate_model.py
├── README.md
└── requirements.txt
```

## Folder Guide

### `data/raw/`

Store original files here.

Examples:

- `.pcap` captures from Wireshark
- raw `.csv` exports from Wireshark or `tshark`

Do not manually edit files in this folder. Keep them as the original source data.

### `data/processed/`

Store cleaned and transformed data here.

Examples:

- feature tables
- cleaned CSV files
- train/test split files

This folder is for data that is ready for modeling.

### `notebooks/`

Use this folder for Jupyter notebooks.

Recommended use:

- explore packet or flow data
- test ideas quickly
- make plots and inspect distributions

`01_exploration.ipynb` is the first notebook for initial data inspection.

### `src/`

Main Python source code lives here.

Files:

- `feature_extraction.py`: turns raw traffic data into ML features
- `train_model.py`: trains a baseline classification model
- `evaluate_model.py`: evaluates the model with metrics such as accuracy, precision, recall, F1-score, and confusion matrix

## Beginner Workflow

1. Capture traffic with Wireshark or export a public dataset.
2. Put original files into `data/raw/`.
3. Explore the data in `notebooks/01_exploration.ipynb`.
4. Build features in `src/feature_extraction.py`.
5. Train a model in `src/train_model.py`.
6. Evaluate results in `src/evaluate_model.py`.

## Suggested Tools

- Wireshark
- Python
- pandas
- scikit-learn
- matplotlib
- tshark or pyshark
- Jupyter Notebook

## Setup

Create and activate a virtual environment, then install dependencies:

```bash
pip install -r requirements.txt
```

Install `tshark` as part of Wireshark if you want to export fields directly from `.pcapng`.

## Analyze Your Current PCAP Files

You currently have:

- `data/raw/youtube_traffic.pcapng`
- `data/raw/browsing_traffic.pcapng`

### 1. Export YouTube traffic to CSV

Use your current Wireshark display filter for the local device IP:

```bash
python src/feature_extraction.py \
  --input data/raw/youtube_traffic.pcapng \
  --output data/processed/youtube_traffic.csv \
  --label YouTube \
  --display-filter "ip.addr == 10.100.1.194" \
  --anonymize
```

### 2. Export Browsing traffic to CSV

If the whole file is browsing traffic, no filter is required:

```bash
python src/feature_extraction.py \
  --input data/raw/browsing_traffic.pcapng \
  --output data/processed/browsing_traffic.csv \
  --label Browsing \
  --anonymize
```

### 3. Export all PCAP/PCAPNG files in one run

If you keep multiple captures in `data/raw/`, you can export all of them at once:

```bash
python src/feature_extraction.py \
  --input-dir data/raw \
  --output-dir data/processed \
  --anonymize
```

The script automatically infers labels from filenames:

- `youtube_traffic.pcapng` -> `YouTube`
- `browsing_traffic.pcapng` -> `Browsing`
- `netflix_capture.pcapng` -> `Netflix`
- `voip_session.pcapng` -> `VoIP`

Batch mode exports the whole file. If one file needs a special Wireshark filter such as `ip.addr == 10.100.1.194`, use single-file mode for that capture.

### 4. What this script exports

The CSV includes beginner-friendly packet fields such as:

- packet number
- timestamp
- packet length
- source IP / destination IP
- protocol
- TCP or UDP ports
- DNS query name
- TLS server name when available

These fields are enough to start exploration and build a first offline dataset.

## GitHub and Privacy

Do not push raw `pcap` or `pcapng` files to a public repository if they contain real private traffic.

Why:

- local IP addresses can reveal your home or lab network structure
- DNS names and TLS hostnames can reveal visited services
- packet captures may contain metadata you do not want to publish

What this project does now:

- `.gitignore` blocks `data/raw/` from being committed
- `.gitignore` also blocks `data/processed/` exports by default
- `--anonymize` replaces IP addresses in CSV with values like `host_001`

Important:

- IP anonymization protects `ip.src` and `ip.dst`
- domain names such as `dns.qry.name` or TLS server names can still be sensitive
- for public GitHub, prefer sharing only sanitized samples or derived features instead of raw packet exports

## Recommended Beginner Workflow For Your Files

1. Keep original captures only in `data/raw/`.
2. Export CSV using `src/feature_extraction.py`.
3. Open the CSV in the notebook and inspect columns.
4. Create a smaller cleaned dataset for ML in `data/processed/`.
5. Commit code, notebooks, and documentation.
6. Do not commit real captures unless the repository is private and you accept the risk.

## Next Steps

- Add a small sample dataset or your own captures
- Start with CSV-based feature extraction before parsing PCAP directly
- Train a simple baseline model such as Random Forest or Logistic Regression
- Track class balance and evaluation metrics carefully
