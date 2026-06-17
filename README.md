# AI-Based Network Traffic Classification

Student portfolio project for classifying offline network traffic captures with Python, Wireshark, and machine learning.

## Project Overview

This project studies how different types of network traffic create different packet-level patterns and how those patterns can be used for classification.

The current version focuses on **offline traffic classification**, not real-time detection.

Target traffic classes in this project:

- `youtube`
- `browsing`
- `download`

The workflow is:

1. capture traffic with Wireshark
2. export selected packet fields with `tshark`
3. build a clean labeled dataset
4. train a baseline machine learning model
5. evaluate the model with standard classification metrics

## Problem Statement

Modern applications generate different traffic signatures.

For example:

- streaming traffic may rely heavily on `QUIC` and `UDP`
- encrypted downloads may show long-lived `TCP` and `TLS` flows
- normal browsing may show more `DNS`, many destinations, and shorter connections

The goal of this project is to learn whether these traffic patterns can be turned into useful machine learning features and used to classify traffic automatically.

## Tools and Technologies

- `Wireshark`
- `tshark`
- `Python`
- `pandas`
- `numpy`
- `scikit-learn`
- `matplotlib`
- `Jupyter Notebook`

## Project Structure

```text
ai-network-traffic-classification/
├── data/
│   ├── raw/
│   └── processed/
├── docs/
├── models/
├── notebooks/
├── src/
├── traffic_signature_analysis/
├── README.md
└── requirements.txt
```

## Dataset Collection

Traffic was collected manually with Wireshark from controlled sessions.

Current capture types:

- `youtube_traffic.pcapng`
- `browsing_traffic.pcapng`
- `download_traffic_1gb.pcapng`

Example capture logic:

- `YouTube`: stream video traffic from device IP `10.100.1.194`
- `Browsing`: open normal web pages from device IP `10.100.1.194`
- `Download`: download a large file from device IP `10.100.1.89`

Important privacy rule:

- raw `pcap` files are **not committed** to public GitHub
- generated CSV exports are also ignored by default
- this project keeps code and documentation public, not sensitive traffic data

For the full collection guide, see:

- [docs/traffic_collection_guide.md](c:/Users/oğuz/ai-network-traffic-classification/docs/traffic_collection_guide.md)

## Feature Extraction

The project uses `tshark` through Python `subprocess` calls to export selected fields from `pcapng` files.

Traffic-specific signature exports are created in:

- `traffic_signature_analysis/youtube_signature.csv`
- `traffic_signature_analysis/browsing_signature.csv`
- `traffic_signature_analysis/download_signature.csv`

Main exported packet-level fields:

- `frame.time_relative`
- `ip.src`
- `ip.dst`
- `ip.proto`
- `tcp.srcport`
- `tcp.dstport`
- `udp.srcport`
- `udp.dstport`
- `frame.len`
- `dns.qry.name`
- `tls.handshake.extensions_server_name`
- `_ws.col.protocol`
- `label`

After that, the Day 3 feature extraction step creates a simpler ML dataset with these final columns:

- `src_ip`
- `dst_ip`
- `src_port`
- `dst_port`
- `protocol`
- `packet_length`
- `time_delta`
- `label`

Final dataset output:

- `data/processed/final_labeled_dataset.csv`

Main scripts:

- [src/traffic_signature_analysis.py](c:/Users/oğuz/ai-network-traffic-classification/src/traffic_signature_analysis.py): export traffic-specific signature CSV files
- [src/feature_extraction.py](c:/Users/oğuz/ai-network-traffic-classification/src/feature_extraction.py): combine exported CSV files into one clean labeled dataset
- [src/analyze_traffic_signatures.py](c:/Users/oğuz/ai-network-traffic-classification/src/analyze_traffic_signatures.py): analyze protocol ratios in Python

## Exploratory Data Analysis

The dataset is explored in Jupyter notebooks using `pandas` and `matplotlib`.

Notebook coverage includes:

- missing value checks
- label distribution
- protocol distribution
- packet length statistics
- class-level comparisons

Relevant notebooks:

- [notebooks/01_exploration.ipynb](c:/Users/oğuz/ai-network-traffic-classification/notebooks/01_exploration.ipynb)
- [notebooks/02_traffic_signature_analysis.ipynb](c:/Users/oğuz/ai-network-traffic-classification/notebooks/02_traffic_signature_analysis.ipynb)
- [notebooks/03_dataset_eda.ipynb](c:/Users/oğuz/ai-network-traffic-classification/notebooks/03_dataset_eda.ipynb)

## Machine Learning Model

The baseline classifier is a `RandomForestClassifier`.

Training pipeline:

1. load `final_labeled_dataset.csv`
2. clean categorical and numeric fields
3. split into train and test sets
4. encode categorical features
5. train the model
6. save the trained model and test outputs

Training script:

- [src/train_model.py](c:/Users/oğuz/ai-network-traffic-classification/src/train_model.py)

Saved model artifacts:

- `models/network_traffic_model.pkl`
- `models/test_dataset.csv`
- `models/test_predictions.csv`
- `models/training_summary.json`

## Evaluation Results

The model is evaluated with:

- `Accuracy`
- `Precision`
- `Recall`
- `F1-score`
- `Classification Report`
- `Confusion Matrix`

Evaluation script:

- [src/evaluate_model.py](c:/Users/oğuz/ai-network-traffic-classification/src/evaluate_model.py)

Saved evaluation outputs:

- `models/evaluation_metrics.json`
- `models/classification_report.txt`
- `models/confusion_matrix.png`

### Results Placeholder

Use this section to document your latest full-dataset run.

Example format:

```text
Accuracy: ...
Precision (weighted): ...
Recall (weighted): ...
F1-score (weighted): ...
```

Short interpretation template:

- Which traffic class was easiest to classify?
- Which class was confused most often?
- Was the dataset balanced enough?
- Which features appeared most useful?

## Traffic Signature Findings

Early analysis showed that each traffic type has a different protocol signature:

- `YouTube` -> mostly `QUIC` + `UDP`
- `Download` -> mostly `TCP` + `TLS`
- `Browsing` -> mostly `TCP` with visible `DNS` and mixed encrypted web traffic

This is important because protocol distribution itself can become a useful feature source for ML classification.

## Setup and Usage

Create and activate a virtual environment, then install requirements:

```bash
pip install -r requirements.txt
```

### 1. Export traffic signature CSV files

```bash
python src/traffic_signature_analysis.py
```

### 2. Build the final labeled dataset

```bash
python src/feature_extraction.py --combine-input-dir traffic_signature_analysis --combine-output data/processed/final_labeled_dataset.csv
```

### 3. Train the baseline model

```bash
python src/train_model.py
```

### 4. Evaluate the model

```bash
python src/evaluate_model.py
```

## What I Learned

This project helped me practice:

- packet capture basics with Wireshark
- the meaning of source IP, destination IP, ports, and protocols
- how `PCAP` files can be converted into machine-learning-friendly tables
- how protocol signatures differ between streaming, browsing, and download traffic
- data cleaning and exploratory data analysis with `pandas`
- supervised classification with `scikit-learn`
- model evaluation with accuracy, precision, recall, F1-score, and confusion matrix
- how to document a technical project for GitHub and portfolio use

## Future Improvements

- add more traffic classes such as `Netflix`, `VoIP`, and `Gaming`
- move from packet-level features to flow-level features
- add feature importance analysis
- test multiple models beyond Random Forest
- improve handling of class imbalance
- add automated experiment tracking
- explore real-time traffic classification

## Portfolio Note

This project is designed as a student-friendly networking + machine learning portfolio project.

It shows practical work in:

- network traffic collection
- packet analysis
- feature engineering
- machine learning
- evaluation
- technical documentation
