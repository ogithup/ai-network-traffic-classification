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

## Next Steps

- Add a small sample dataset or your own captures
- Start with CSV-based feature extraction before parsing PCAP directly
- Train a simple baseline model such as Random Forest or Logistic Regression
- Track class balance and evaluation metrics carefully
