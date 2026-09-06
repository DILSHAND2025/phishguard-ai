"""
MAVERICK — Machine Learning Prediction Engine & FastAPI Microservice
Smart India Hackathon 2026
"""

import os
import re
import json
import argparse
from typing import List, Dict, Any, Optional
import joblib
import numpy as np

try:
    from fastapi import FastAPI, HTTPException, status
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, Field
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

try:
    from ml.train import clean_text
except ImportError:
    import sys
    sys.path.append(os.path.dirname(__file__))
    from train import clean_text

MODEL_DIR = os.path.join(os.path.dirname(__file__), "model")
VEC_PATH = os.path.join(MODEL_DIR, "vectorizer.pkl")
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")

# Global cached model instances
_vectorizer = None
_model = None

def load_artifacts():
    global _vectorizer, _model
    if _vectorizer is None or _model is None:
        if not os.path.exists(VEC_PATH) or not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"Model artifacts missing. Expected {VEC_PATH} and {MODEL_PATH}. "
                "Run `python ml/train.py` first to train the model."
            )
        _vectorizer = joblib.load(VEC_PATH)
        _model = joblib.load(MODEL_PATH)
    return _vectorizer, _model

def predict_threat(text: str) -> Dict[str, Any]:
    """
    Perform genuine ML inference on raw email text.
    Handles empty, very short, and edge-case inputs gracefully.
    """
    # 1. Input validation
    if text is None or not isinstance(text, str):
        return {
            "prediction": "unknown",
            "phishing_probability": 0.0,
            "legitimate_probability": 0.0,
            "confidence": 0.0,
            "model": "TF-IDF + Logistic Regression",
            "error": "Input must be a non-null string",
            "status": "INVALID_INPUT"
        }

    cleaned = clean_text(text)
    if len(cleaned.strip()) < 3:
        return {
            "prediction": "legitimate",
            "phishing_probability": 0.05,
            "legitimate_probability": 0.95,
            "confidence": 0.95,
            "model": "TF-IDF + Logistic Regression",
            "top_features": [],
            "note": "Text length too short for high-confidence lexical analysis",
            "status": "SUCCESS"
        }

    # 2. Load model
    vectorizer, model = load_artifacts()

    # 3. Vectorize text
    vec = vectorizer.transform([cleaned])

    # 4. Predict class & probability
    probs = model.predict_proba(vec)[0]
    legit_prob = float(probs[0])
    phish_prob = float(probs[1])
    predicted_class = "phishing" if phish_prob >= 0.5 else "legitimate"

    # 5. Extract active TF-IDF terms in this email with their learned model coefficients
    feature_names = vectorizer.get_feature_names_out()
    coefs = model.coef_[0]
    non_zero_indices = vec.nonzero()[1]

    contributing_terms = []
    for idx in non_zero_indices:
        term = feature_names[idx]
        tfidf_val = vec[0, idx]
        coef_val = coefs[idx]
        contribution = tfidf_val * coef_val
        contributing_terms.append({
            "term": term,
            "weight": round(float(coef_val), 4),
            "tfidf": round(float(tfidf_val), 4),
            "impact": round(float(contribution), 4),
            "indicator": "PHISHING" if coef_val > 0 else "BENIGN"
        })

    # Sort terms by absolute impact
    contributing_terms.sort(key=lambda x: abs(x["impact"]), reverse=True)

    return {
        "prediction": predicted_class,
        "phishing_probability": round(phish_prob, 4),
        "legitimate_probability": round(legit_prob, 4),
        "confidence": round(max(phish_prob, legit_prob), 4),
        "model": "TF-IDF + Logistic Regression",
        "top_features": contributing_terms[:8],
        "status": "SUCCESS"
    }

# ----------------------------------------------------------------------
# FastAPI Microservice Definition
# ----------------------------------------------------------------------
if FASTAPI_AVAILABLE:
    app = FastAPI(
        title="MAVERICK AI Threat Detection Service",
        description="Real ML TF-IDF + Logistic Regression Phishing Classifier API (SIH 2026)",
        version="1.0.0"
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    class PredictRequest(BaseModel):
        text: Optional[str] = Field(default="", description="Email subject and body text to analyze")

    class PredictResponse(BaseModel):
        prediction: str
        phishing_probability: float
        legitimate_probability: float
        model: str
        confidence: Optional[float] = None
        top_features: Optional[List[Dict[str, Any]]] = None
        status: Optional[str] = None
        note: Optional[str] = None

    @app.get("/health")
    def health_check():
        artifacts_exist = os.path.exists(VEC_PATH) and os.path.exists(MODEL_PATH)
        return {
            "status": "online" if artifacts_exist else "model_missing",
            "service": "MAVERICK ML Inference Engine",
            "model_type": "TF-IDF + Logistic Regression",
            "artifacts_loaded": _model is not None,
            "vectorizer_path": VEC_PATH,
            "model_path": MODEL_PATH
        }

    @app.post("/predict", response_model=PredictResponse)
    def predict_endpoint(req: PredictRequest):
        try:
            result = predict_threat(req.text or "")
            if result.get("status") == "INVALID_INPUT":
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=result.get("error"))
            return result
        except FileNotFoundError as e:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Prediction failure: {str(e)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MAVERICK ML Inference Tool")
    parser.add_argument("--text", type=str, help="Email text to evaluate")
    parser.add_argument("--serve", action="store_true", help="Start FastAPI HTTP prediction server")
    parser.add_argument("--host", default="127.0.0.1", help="Host address")
    parser.add_argument("--port", type=int, default=8000, help="Port number")
    args = parser.parse_args()

    if args.serve:
        if not FASTAPI_AVAILABLE:
            print("Error: FastAPI or Uvicorn not installed.")
            exit(1)
        import uvicorn
        print(f"[*] Starting MAVERICK ML Inference Service on http://{args.host}:{args.port}")
        uvicorn.run(app, host=args.host, port=args.port)
    elif args.text:
        result = predict_threat(args.text)
        print(json.dumps(result, indent=2))
    else:
        # Default demo prediction
        sample = "URGENT: Wire transfer authorization required immediately. Statutory allocation directive applies."
        print(f"[*] Sample Input: {sample}")
        print("[*] Running ML Inference...")
        result = predict_threat(sample)
        print(json.dumps(result, indent=2))
