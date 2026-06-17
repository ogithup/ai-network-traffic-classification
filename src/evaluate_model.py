"""
Gün 6 - Model değerlendirme script'i.

Bu script:
1. Eğitilmiş RandomForest pipeline modelini yükler
2. Kaydedilmiş test verisini yükler
3. Test verisi üzerinde tekrar tahmin üretir
4. Accuracy, precision, recall, F1-score, classification report ve confusion matrix hesaplar

Basit yorum mantığı:
- Accuracy: Genel olarak ne kadar doğru tahmin yaptık?
- Precision: Model bir sınıf dediğinde ne kadar doğru söylüyor?
- Recall: Gerçek sınıf örneklerinin ne kadarını yakalıyor?
- F1-score: Precision ve recall arasında dengeli bir ölçü
- Confusion matrix: Hangi sınıf hangi sınıfla karışıyor?
"""

from __future__ import annotations

import argparse
import json
import pickle
from pathlib import Path

import matplotlib
import pandas as pd
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)


# Grafik dosyasını ekrana açmadan kaydetmek için GUI istemeyen backend kullanılır.
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Load a trained model and test data, then evaluate classification performance."
    )
    parser.add_argument(
        "--model",
        default="models/network_traffic_model.pkl",
        help="Path to the trained model bundle saved by train_model.py.",
    )
    parser.add_argument(
        "--test-data",
        default="models/test_dataset.csv",
        help="Path to the saved test dataset CSV.",
    )
    parser.add_argument(
        "--output-dir",
        default="models",
        help="Directory where evaluation outputs will be written.",
    )
    return parser


def load_model_bundle(model_path: Path) -> dict[str, object]:
    """Kaydedilmiş model bundle dosyasını yükle."""
    if not model_path.exists():
        raise FileNotFoundError(f"Model file not found: {model_path}")

    with model_path.open("rb") as file_handle:
        bundle = pickle.load(file_handle)

    required_keys = {"pipeline", "feature_columns", "target_column"}
    if not required_keys.issubset(bundle.keys()):
        raise ValueError("Model bundle is missing required keys.")

    return bundle


def load_test_dataset(test_data_path: Path, feature_columns: list[str], target_column: str) -> pd.DataFrame:
    """Kaydedilmiş test veri setini oku ve gerekli sütunları kontrol et."""
    if not test_data_path.exists():
        raise FileNotFoundError(f"Test dataset file not found: {test_data_path}")

    dataframe = pd.read_csv(test_data_path, low_memory=False)
    required_columns = set(feature_columns + [target_column])
    if not required_columns.issubset(dataframe.columns):
        raise ValueError(f"Test dataset is missing required columns: {sorted(required_columns - set(dataframe.columns))}")

    return dataframe


def save_evaluation_files(y_true: pd.Series, y_pred: pd.Series, output_dir: Path) -> tuple[Path, Path]:
    """
    Metrikleri JSON ve metin olarak kaydet.

    Accuracy:
    - Tüm tahminler içindeki doğru tahmin oranıdır.

    Precision:
    - Model bir sınıf dediğinde ne kadar güvenilir olduğunu gösterir.

    Recall:
    - Gerçek örneklerin ne kadarını yakaladığını gösterir.

    F1-score:
    - Precision ve recall arasında dengeli bir ortalamadır.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    metrics_summary = {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision_weighted": precision_score(y_true, y_pred, average="weighted", zero_division=0),
        "recall_weighted": recall_score(y_true, y_pred, average="weighted", zero_division=0),
        "f1_weighted": f1_score(y_true, y_pred, average="weighted", zero_division=0),
        "classification_report": classification_report(y_true, y_pred, zero_division=0, output_dict=True),
    }

    json_path = output_dir / "evaluation_metrics.json"
    json_path.write_text(json.dumps(metrics_summary, indent=2), encoding="utf-8")

    text_path = output_dir / "classification_report.txt"
    text_path.write_text(
        classification_report(y_true, y_pred, zero_division=0),
        encoding="utf-8",
    )

    return json_path, text_path


def save_predictions(y_true: pd.Series, y_pred: pd.Series, output_dir: Path) -> Path:
    """Üretilen tahminleri CSV olarak kaydet."""
    output_dir.mkdir(parents=True, exist_ok=True)
    predictions_path = output_dir / "test_predictions.csv"
    pd.DataFrame({"y_true": y_true, "y_pred": y_pred}).to_csv(predictions_path, index=False)
    return predictions_path


def save_confusion_matrix_figure(y_true: pd.Series, y_pred: pd.Series, output_dir: Path) -> Path:
    """
    Confusion matrix çiz.

    Confusion matrix neden önemli:
    - Sadece genel başarıyı değil, hata tiplerini de gösterir.
    - Örneğin browsing paketleri youtube olarak mı tahmin edilmiş,
      yoksa download ile mi karışmış bunu görebiliriz.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    labels = sorted(pd.unique(pd.concat([y_true, y_pred], ignore_index=True)))

    matrix = confusion_matrix(y_true, y_pred, labels=labels)
    figure, axis = plt.subplots(figsize=(8, 6))
    display = ConfusionMatrixDisplay(confusion_matrix=matrix, display_labels=labels)
    display.plot(ax=axis, cmap="Blues", colorbar=False)
    axis.set_title("Network Traffic Classification Confusion Matrix")
    plt.tight_layout()

    output_path = output_dir / "confusion_matrix.png"
    figure.savefig(output_path, dpi=150)
    plt.close(figure)
    return output_path


def main() -> None:
    args = build_parser().parse_args()
    model_path = Path(args.model)
    test_data_path = Path(args.test_data)
    output_dir = Path(args.output_dir)

    bundle = load_model_bundle(model_path)
    pipeline = bundle["pipeline"]
    feature_columns = bundle["feature_columns"]
    target_column = bundle["target_column"]

    test_df = load_test_dataset(test_data_path, feature_columns, target_column)
    x_test = test_df[feature_columns]
    y_true = test_df[target_column]
    y_pred = pd.Series(pipeline.predict(x_test), name="y_pred")

    predictions_path = save_predictions(y_true.reset_index(drop=True), y_pred, output_dir)
    json_path, text_path = save_evaluation_files(y_true, y_pred, output_dir)
    matrix_path = save_confusion_matrix_figure(y_true, y_pred, output_dir)

    print(f"Predictions saved to: {predictions_path}")
    print(f"Evaluation JSON saved to: {json_path}")
    print(f"Classification report saved to: {text_path}")
    print(f"Confusion matrix saved to: {matrix_path}")
    print(f"Accuracy: {accuracy_score(y_true, y_pred):.4f}")
    print(f"Precision (weighted): {precision_score(y_true, y_pred, average='weighted', zero_division=0):.4f}")
    print(f"Recall (weighted): {recall_score(y_true, y_pred, average='weighted', zero_division=0):.4f}")
    print(f"F1-score (weighted): {f1_score(y_true, y_pred, average='weighted', zero_division=0):.4f}")
    print(classification_report(y_true, y_pred, zero_division=0))


if __name__ == "__main__":
    main()
