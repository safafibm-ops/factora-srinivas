"""
Factora - Agent 2: Cyber Threat Correlator Model Trainer
Problem 1: Safety Tech — FAKE OR REAL (Hackathon 2026)

Trains an ensemble Random Forest Correlation Classifier on training_pairs.csv using:
1. Semantic TF-IDF embedding cosine similarity of threat titles & descriptions.
2. Domain/URL fuzzy Levenshtein similarity.
3. Exact/partial overlap of contact indicators (email, phone, UPI ID).
4. Shared GitHub repository & suspicious npm/pip package indicators.
5. Student scam flags agreement.

Outputs:
- backend/agent2_correlator/models/correlator_rf_model.joblib
- Prints accuracy, precision, recall, and F1-score.
"""

import json
import csv
import difflib
from pathlib import Path
from typing import Dict, Any, List, Tuple

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    roc_auc_score,
)
import joblib


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)


def load_incidents_dict(json_path: Path) -> Dict[str, Dict[str, Any]]:
    """Loads incidents mapped by their incident_id."""
    with open(json_path, "r", encoding="utf-8") as f:
        incidents = json.load(f)
    return {inc["incident_id"]: inc for inc in incidents}


def build_semantic_vectorizer(incidents: Dict[str, Dict[str, Any]]) -> TfidfVectorizer:
    """Fits a TF-IDF semantic vectorizer over all incident texts."""
    corpus = [
        f"{inc['incident_title']} {inc['description']} {inc.get('claimed_organization', '')}"
        for inc in incidents.values()
    ]
    vectorizer = TfidfVectorizer(
        max_features=256,
        ngram_range=(1, 2),
        stop_words="english",
        sublinear_tf=True
    )
    vectorizer.fit(corpus)
    return vectorizer


def compute_semantic_sim(
    text_a: str,
    text_b: str,
    vectorizer: TfidfVectorizer
) -> float:
    """Calculates cosine similarity between two text snippets using TF-IDF vectors."""
    vec_a = vectorizer.transform([text_a])
    vec_b = vectorizer.transform([text_b])
    sim = cosine_similarity(vec_a, vec_b)[0][0]
    return float(sim)


def prepare_training_dataset(
    csv_path: Path,
    incidents_dict: Dict[str, Dict[str, Any]],
    vectorizer: TfidfVectorizer
) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """
    Parses training pairs CSV and computes enriched ML feature matrix.
    """
    X_rows = []
    y_labels = []

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            id_a = row["incident_id_a"]
            id_b = row["incident_id_b"]
            
            inc_a = incidents_dict.get(id_a, {})
            inc_b = incidents_dict.get(id_b, {})

            text_a = f"{inc_a.get('incident_title', '')} {inc_a.get('description', '')}"
            text_b = f"{inc_b.get('incident_title', '')} {inc_b.get('description', '')}"

            # 1. Semantic Embedding Cosine Similarity
            semantic_cos_sim = compute_semantic_sim(text_a, text_b, vectorizer)

            # 2. Domain Fuzzy Similarity (Levenshtein)
            domain_sim = float(row.get("domain_similarity", 0.0))

            # 3. Exact Shared Indicators
            shared_domains = float(row.get("shared_domains_count", 0.0))
            shared_contacts = float(row.get("shared_contacts_count", 0.0))
            shared_repos = float(row.get("shared_repos_count", 0.0))
            shared_packages = float(row.get("shared_packages_count", 0.0))
            shared_flags = float(row.get("shared_scam_flags_count", 0.0))

            feature_vector = [
                semantic_cos_sim,
                domain_sim,
                shared_domains,
                shared_contacts,
                shared_repos,
                shared_packages,
                shared_flags
            ]

            X_rows.append(feature_vector)
            y_labels.append(int(row["is_connected_label"]))

    feature_names = [
        "semantic_cosine_sim",
        "domain_similarity",
        "shared_domains_count",
        "shared_contacts_count",
        "shared_repos_count",
        "shared_packages_count",
        "shared_scam_flags_count"
    ]

    return np.array(X_rows, dtype=np.float32), np.array(y_labels, dtype=np.int32), feature_names


def train_and_evaluate_model():
    """Trains the Random Forest model, evaluates performance, and persists artifact."""
    json_path = DATA_DIR / "historical_incidents.json"
    if not json_path.exists():
        json_path = BASE_DIR / "historical_incidents.json"

    csv_path = DATA_DIR / "training_pairs.csv"
    if not csv_path.exists():
        csv_path = BASE_DIR / "training_pairs.csv"

    print("=" * 60)
    print(" FACTORA AGENT 2: TRAINING THREAT CORRELATION AI MODEL")
    print("=" * 60)
    print(f"Loading incidents: {json_path}")
    print(f"Loading training pairs: {csv_path}")

    incidents_dict = load_incidents_dict(json_path)
    print(f"Loaded {len(incidents_dict)} historical incidents.")

    # 1. Fit Semantic Vectorizer
    vectorizer = build_semantic_vectorizer(incidents_dict)
    print("Semantic TF-IDF Vectorizer initialized & vocabulary fitted.")

    # 2. Extract Features
    X, y, feature_names = prepare_training_dataset(csv_path, incidents_dict, vectorizer)
    print(f"Total Training Samples: {X.shape[0]} pairs with {X.shape[1]} features each.")
    print(f"Class Balance: {sum(y == 1)} Connected pairs vs {sum(y == 0)} Non-Connected.")

    # 3. Train-Test Split (Stratified to maintain class balance)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    print(f"Train split: {len(X_train)} | Test split: {len(X_test)}")

    # 4. Train Random Forest Classifier
    rf_model = RandomForestClassifier(
        n_estimators=120,
        max_depth=6,
        class_weight="balanced",  # Accounts for class imbalance (35 pos vs 265 neg)
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)

    # 5. Evaluate on Held-Out Test Set
    y_pred = rf_model.predict(X_test)
    y_prob = rf_model.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    roc_auc = roc_auc_score(y_test, y_prob)

    print("\n" + "-" * 40)
    print(" [MODEL EVALUATION METRICS (Test Set)]")
    print("-" * 40)
    print(f" Accuracy:  {acc * 100:.2f}%")
    print(f" Precision: {prec * 100:.2f}%")
    print(f" Recall:    {rec * 100:.2f}%")
    print(f" F1-Score:  {f1 * 100:.2f}%")
    print(f" ROC-AUC:   {roc_auc:.4f}")

    print("\nFeature Importances:")
    importances = rf_model.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    for idx in sorted_idx:
        print(f"  * {feature_names[idx]:<25}: {importances[idx]:.4f}")

    # 6. Fit Final Model on 100% of the dataset for optimal production coverage
    final_rf_model = RandomForestClassifier(
        n_estimators=150,
        max_depth=6,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    final_rf_model.fit(X, y)

    # 7. Package and Persist Pipeline Bundle
    model_bundle = {
        "model": final_rf_model,
        "vectorizer": vectorizer,
        "feature_names": feature_names,
        "metrics": {
            "accuracy": float(acc),
            "precision": float(prec),
            "recall": float(rec),
            "f1_score": float(f1),
            "roc_auc": float(roc_auc)
        },
        "description": "Factora Cyber Threat Correlation Random Forest Classifier"
    }

    model_output_path = MODELS_DIR / "correlator_rf_model.joblib"
    joblib.dump(model_bundle, model_output_path)
    print(f"\n[OK] Successfully saved trained AI model to:\n     {model_output_path}")

    return model_output_path


if __name__ == "__main__":
    train_and_evaluate_model()
