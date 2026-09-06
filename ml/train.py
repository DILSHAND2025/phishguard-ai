"""
MAVERICK — Real Machine Learning Threat Detection Pipeline
Model: TF-IDF Vectorizer + Logistic Regression Classifier
Smart India Hackathon 2026
"""

import os
import re
import json
import argparse
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)
import joblib

RANDOM_SEED = 42

def clean_text(text: str) -> str:
    """
    Standard text preprocessing pipeline:
    - Lowercasing
    - Stripping URLs, HTML tags, email addresses
    - Removing non-alphanumeric punctuation
    - Normalizing whitespaces
    """
    if not isinstance(text, str):
        return ""
    
    text = text.lower()
    text = re.sub(r'<[^>]+>', ' ', text)  # strip HTML tags
    text = re.sub(r'https?://\S+|www\.\S+', ' url_token ', text)  # normalize URLs
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', ' email_token ', text)
    text = re.sub(r'[^a-zA-Z0-9_\s]', ' ', text)  # keep words and tokens
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def train(dataset_path: str = "ml/dataset/phishing_emails.csv", model_dir: str = "ml/model"):
    """
    Train TF-IDF + Logistic Regression model and serialize artifacts.
    """
    print("=" * 65)
    print(" MAVERICK — Training Real AI/ML Phishing Threat Detection Model")
    print("=" * 65)

    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset file not found at: {dataset_path}")

    # 1. Load data
    print(f"[*] Loading dataset from: {dataset_path}")
    df = pd.read_csv(dataset_path)

    # 2. Missing value handling
    initial_count = len(df)
    df = df.dropna(subset=['text', 'label'])
    df['label'] = df['label'].astype(int)
    print(f"[*] Total valid samples: {len(df)} (Dropped {initial_count - len(df)} empty rows)")
    
    class_counts = df['label'].value_counts().to_dict()
    print(f"[*] Class distribution: Legitimate (0) = {class_counts.get(0, 0)}, Phishing (1) = {class_counts.get(1, 0)}")

    # 3. Preprocess text
    print("[*] Preprocessing text...")
    df['cleaned_text'] = df['text'].apply(clean_text)
    
    # Filter empty after cleaning
    df = df[df['cleaned_text'].str.len() > 2]

    X = df['cleaned_text']
    y = df['label']

    # 4. Train/Test split (80% train, 20% test with stratified split)
    print(f"[*] Splitting dataset (80% train, 20% test, random_state={RANDOM_SEED})...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y
    )
    print(f"    - Training set size: {len(X_train)}")
    print(f"    - Test set size:     {len(X_test)}")

    # 5. TF-IDF Vectorization
    print("[*] Fitting TF-IDF Vectorizer (ngram_range=(1, 2), max_features=2500)...")
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=2500,
        sublinear_tf=True,
        min_df=1,
        stop_words='english'
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    print(f"[*] Vocabulary size: {len(vectorizer.vocabulary_)} features")

    # 6. Train Logistic Regression
    print("[*] Training Logistic Regression model (C=1.5, max_iter=1000)...")
    model = LogisticRegression(
        C=1.5,
        solver='lbfgs',
        max_iter=1000,
        random_state=RANDOM_SEED
    )
    model.fit(X_train_vec, y_train)

    # 7. Model Evaluation
    print("[*] Evaluating model on test set...")
    y_pred = model.predict(X_test_vec)
    y_pred_proba = model.predict_proba(X_test_vec)[:, 1]

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, pos_label=1, zero_division=0))
    rec = float(recall_score(y_test, y_pred, pos_label=1, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, pos_label=1, zero_division=0))
    cm = confusion_matrix(y_test, y_pred).tolist()
    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

    # Extract top predictive features for Phishing (positive weights) and Legitimate (negative weights)
    feature_names = np.array(vectorizer.get_feature_names_out())
    coefs = model.coef_[0]
    top_phish_idx = np.argsort(coefs)[-12:][::-1]
    top_legit_idx = np.argsort(coefs)[:12]

    top_phish_features = [{"term": str(feature_names[i]), "weight": float(coefs[i])} for i in top_phish_idx]
    top_legit_features = [{"term": str(feature_names[i]), "weight": float(coefs[i])} for i in top_legit_idx]

    print("\n--- MODEL EVALUATION RESULTS ---")
    print(f"  Accuracy:         {acc * 100:.2f}%")
    print(f"  Precision (Phish): {prec * 100:.2f}%")
    print(f"  Recall (Phish):    {rec * 100:.2f}%")
    print(f"  F1-Score (Phish):  {f1 * 100:.2f}%")
    print(f"  Confusion Matrix: TN={cm[0][0]}, FP={cm[0][1]}, FN={cm[1][0]}, TP={cm[1][1]}")

    # 8. Model Serialization
    os.makedirs(model_dir, exist_ok=True)
    vec_path = os.path.join(model_dir, "vectorizer.pkl")
    model_path = os.path.join(model_dir, "phishing_model.pkl")
    metrics_path = os.path.join(model_dir, "evaluation_metrics.json")

    print(f"\n[*] Saving vectorizer to: {vec_path}")
    joblib.dump(vectorizer, vec_path)

    print(f"[*] Saving model to:      {model_path}")
    joblib.dump(model, model_path)

    metrics_payload = {
        "model_type": "TF-IDF + Logistic Regression",
        "dataset_path": dataset_path,
        "total_samples": len(df),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "train_test_split": "80/20",
        "random_state": RANDOM_SEED,
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "confusion_matrix": {
                "true_negative": cm[0][0],
                "false_positive": cm[0][1],
                "false_negative": cm[1][0],
                "true_positive": cm[1][1]
            }
        },
        "classification_report": report,
        "top_phishing_indicators": top_phish_features,
        "top_legitimate_indicators": top_legit_features
    }

    with open(metrics_path, "w") as f:
        json.dump(metrics_payload, f, indent=2)

    print(f"[*] Saved evaluation metrics to: {metrics_path}")
    print("=" * 65)
    print(" [+] Model Training & Serialization Complete!")
    print("=" * 65)

    return metrics_payload

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train MAVERICK AI Threat Detection Model")
    parser.add_argument("--dataset", default="ml/dataset/phishing_emails.csv", help="Path to training CSV")
    parser.add_argument("--model-dir", default="ml/model", help="Directory to save serialized models")
    args = parser.parse_args()

    train(args.dataset, args.model_dir)
