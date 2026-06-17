"""
Gün 5 - Basit model eğitimi.

Bu script, Day 3'te oluşturulan `final_labeled_dataset.csv` dosyasını okuyup
başlangıç seviyesinde bir trafik sınıflandırma modeli eğitir.

Kullandığı temel fikir:
1. Veriyi oku
2. Gerekli feature sütunlarını seç
3. Train / test olarak ayır
4. Kategorik sütunları sayısal hale getir
5. RandomForest ile modeli eğit
6. Test sonuçlarını ve modeli kaydet
"""

from __future__ import annotations

import argparse
import json
import pickle
from pathlib import Path

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OrdinalEncoder


FEATURE_COLUMNS = [
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "packet_length",
    "time_delta",
]

TARGET_COLUMN = "label"
CATEGORICAL_COLUMNS = ["src_ip", "dst_ip", "protocol"]
NUMERIC_COLUMNS = ["src_port", "dst_port", "packet_length", "time_delta"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Train a beginner-friendly network traffic classification model."
    )
    parser.add_argument(
        "--input",
        default="data/processed/final_labeled_dataset.csv",
        help="Path to the final labeled dataset CSV.",
    )
    parser.add_argument(
        "--output-dir",
        default="models",
        help="Directory where the trained model and evaluation files will be saved.",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=None,
        help="Optional row sample size for quicker experiments.",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Test split ratio. Default is 0.2 for 80/20 split.",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed for reproducible results.",
    )
    return parser


def load_dataset(dataset_path: Path) -> pd.DataFrame:
    """Veriyi oku ve gerekli sütunlar var mı kontrol et."""
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset file not found: {dataset_path}")

    dataframe = pd.read_csv(dataset_path, low_memory=False)
    missing_columns = [column for column in FEATURE_COLUMNS + [TARGET_COLUMN] if column not in dataframe.columns]
    if missing_columns:
        raise ValueError(f"Dataset is missing required columns: {missing_columns}")

    return dataframe


def clean_dataset(dataframe: pd.DataFrame) -> pd.DataFrame:
    """
    Model eğitimi öncesi basit temizlik yap.

    Neden gerekli:
    - boş IP / protocol alanları sorun çıkarabilir
    - sayısal alanların gerçekten sayısal olması gerekir
    - label boşsa o satır ML için kullanılamaz
    """
    df = dataframe.copy()

    for column in CATEGORICAL_COLUMNS + [TARGET_COLUMN]:
        df[column] = df[column].fillna("").astype(str).str.strip()

    for column in NUMERIC_COLUMNS:
        df[column] = pd.to_numeric(df[column], errors="coerce").fillna(0)

    df = df[df[TARGET_COLUMN] != ""].reset_index(drop=True)
    return df


def sample_dataset(dataframe: pd.DataFrame, sample_size: int | None, random_state: int) -> pd.DataFrame:
    """İsteğe bağlı örnekleme; büyük veriyle hızlı denemeler için faydalı."""
    if sample_size is None or sample_size >= len(dataframe):
        return dataframe

    sampled_groups: list[pd.DataFrame] = []
    for _, group in dataframe.groupby(TARGET_COLUMN):
        group_sample_size = max(1, round(len(group) / len(dataframe) * sample_size))
        group_sample_size = min(group_sample_size, len(group))
        sampled_groups.append(group.sample(n=group_sample_size, random_state=random_state))

    return pd.concat(sampled_groups, ignore_index=True)


def build_pipeline() -> Pipeline:
    """
    Kategorik ve sayısal sütunları birlikte işleyebilen pipeline kur.

    Burada `OrdinalEncoder` seçiyoruz çünkü:
    - başlangıç seviyesi için anlaşılır
    - RandomForest ile birlikte doğrudan kullanılabilir
    - yeni / bilinmeyen kategori gelirse hata vermemesi için `unknown_value=-1` kullanılır
    """
    preprocessor = ColumnTransformer(
        transformers=[
            (
                "categorical",
                OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1),
                CATEGORICAL_COLUMNS,
            ),
            ("numeric", "passthrough", NUMERIC_COLUMNS),
        ]
    )

    model = RandomForestClassifier(
        n_estimators=120,
        max_depth=20,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced_subsample",
    )

    return Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("model", model),
        ]
    )


def save_model_bundle(pipeline: Pipeline, output_dir: Path) -> Path:
    """Eğitilen modeli tekrar kullanmak için pickle ile kaydet."""
    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = output_dir / "network_traffic_model.pkl"
    bundle = {
        "pipeline": pipeline,
        "feature_columns": FEATURE_COLUMNS,
        "target_column": TARGET_COLUMN,
    }

    with model_path.open("wb") as file_handle:
        pickle.dump(bundle, file_handle)

    return model_path


def save_test_predictions(y_true: pd.Series, y_pred: pd.Series, output_dir: Path) -> Path:
    """Evaluate script'inin kullanması için gerçek ve tahmin edilen label'ları kaydet."""
    output_dir.mkdir(parents=True, exist_ok=True)
    predictions_path = output_dir / "test_predictions.csv"
    prediction_df = pd.DataFrame({"y_true": y_true, "y_pred": y_pred})
    prediction_df.to_csv(predictions_path, index=False)
    return predictions_path


def save_test_dataset(x_test: pd.DataFrame, y_test: pd.Series, output_dir: Path) -> Path:
    """
    Evaluate script'inin modeli tekrar çalıştırabilmesi için test verisini kaydet.

    Neden gerekli:
    - Gün 6'da evaluate_model.py sadece hazır tahminleri okumakla kalmasın
    - gerçekten modeli yükleyip test verisi üzerinde tekrar tahmin üretsin
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    test_data_path = output_dir / "test_dataset.csv"
    test_df = x_test.copy().reset_index(drop=True)
    test_df[TARGET_COLUMN] = y_test.reset_index(drop=True)
    test_df.to_csv(test_data_path, index=False)
    return test_data_path


def save_training_summary(y_true: pd.Series, y_pred: pd.Series, output_dir: Path) -> Path:
    """Temel metrikleri JSON olarak sakla."""
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "training_summary.json"

    summary = {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision_weighted": precision_score(y_true, y_pred, average="weighted", zero_division=0),
        "recall_weighted": recall_score(y_true, y_pred, average="weighted", zero_division=0),
        "f1_weighted": f1_score(y_true, y_pred, average="weighted", zero_division=0),
        "classification_report": classification_report(y_true, y_pred, zero_division=0, output_dict=True),
    }

    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary_path


def main() -> None:
    args = build_parser().parse_args()
    dataset_path = Path(args.input)
    output_dir = Path(args.output_dir)

    dataframe = load_dataset(dataset_path)
    dataframe = clean_dataset(dataframe)
    dataframe = sample_dataset(dataframe, args.sample_size, args.random_state)

    x = dataframe[FEATURE_COLUMNS]
    y = dataframe[TARGET_COLUMN]

    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=args.test_size,
        random_state=args.random_state,
        stratify=y,
    )

    pipeline = build_pipeline()
    pipeline.fit(x_train, y_train)

    y_pred = pipeline.predict(x_test)

    model_path = save_model_bundle(pipeline, output_dir)
    test_data_path = save_test_dataset(x_test, y_test, output_dir)
    predictions_path = save_test_predictions(y_test.reset_index(drop=True), pd.Series(y_pred), output_dir)
    summary_path = save_training_summary(y_test, y_pred, output_dir)

    print(f"Training completed with {len(dataframe)} rows.")
    print(f"Model saved to: {model_path}")
    print(f"Test dataset saved to: {test_data_path}")
    print(f"Predictions saved to: {predictions_path}")
    print(f"Summary saved to: {summary_path}")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(classification_report(y_test, y_pred, zero_division=0))


if __name__ == "__main__":
    main()
