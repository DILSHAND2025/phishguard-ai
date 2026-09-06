# MAVERICK — AI/ML Phishing Threat Detection Subsystem
**Smart India Hackathon 2026**

---

## 1. Overview & Architecture

MAVERICK integrates a dedicated, genuine machine-learning inference pipeline designed to analyze email text (subject, body headers, and snippet) and calculate probabilistic phishing threat classifications.

The ML prediction functions as **one evidence source** in MAVERICK's multi-layered evidence fusion and forensic risk-scoring engine. The ML score informs Layer 1 (AI/NLP Threat Detection, maximum 25 points out of 100) and **does not** dictate the final risk score alone.

```
Email Input (.eml / MIME)
         │
         ▼
Email Parser & RFC 822 Extraction
         │
         ├───────────────────────────────────────────┐
         │                                           │
         ▼                                           ▼
Header & DNS Forensics                      Email Text Extraction
(SPF / DKIM / DMARC)                        (Subject + Body Content)
         │                                           │
         ▼                                           ▼
IOC Extraction & Enrichment                 Text Preprocessing
(IPs, Domains, URLs, Hashes)               (Normalize, URL/Email tokens)
         │                                           │
         ▼                                           ▼
GeoLocation & ASN Context                   TF-IDF Vectorizer
         │                                 (1-2 N-grams, 2500 features)
         │                                           │
         │                                           ▼
         │                                  Trained Logistic Regression
         │                                           │
         │                                           ▼
         │                                  Phishing Probability & Features
         │                                           │
         └───────────────────┬───────────────────────┘
                             │
                             ▼
              Multi-Layer Evidence Fusion Engine
                (6 Weighted Evidence Layers)
                             │
                             ▼
                 Final MAVERICK Risk Score
                  (0 - 100 Forensic Rating)
```

---

## 2. Dataset

- **Path:** [`ml/dataset/phishing_emails.csv`](file:///d:/SIH%202026/maverick/ml/dataset/phishing_emails.csv)
- **Format:** `text,label` CSV
  - `label = 0`: Legitimate business/operational email
  - `label = 1`: Phishing / Business Email Compromise (BEC) / Credential harvesting / Wire diversion
- **Total Samples:** 80 curated representative emails (40 legitimate, 40 phishing)
- **Phishing Archetypes Covered:**
  - Executive BEC & statutory bypass directives
  - Immediate wire remittance and banking diversion
  - SSO / 2FA / Okta / Microsoft credential harvesting
  - Urgent account suspension warnings and fake security alerts
  - Malicious attachment lures (double extensions, invoice macros)
- **Legitimate Archetypes Covered:**
  - Weekly status reports, sprint standups, quarterly reviews
  - Routine IT maintenance schedules, scheduled downtime notices
  - Benign customer inquiries, vendor agreements, project deliverables

---

## 3. Text Preprocessing Pipeline

Implemented in both [`ml/train.py`](file:///d:/SIH%202026/maverick/ml/train.py) and [`src/services/aiThreatModel.js`](file:///d:/SIH%202026/maverick/src/services/aiThreatModel.js):
1. **Lowercasing:** Normalizes case variations.
2. **HTML Stripping:** Eliminates markup artifacts while preserving enclosed tokens.
3. **URL Tokenization:** Replaces hyperlinks (`https://...`, `www...`) with `url_token`.
4. **Email Tokenization:** Replaces email addresses with `email_token`.
5. **Punctuation Normalization:** Removes non-alphanumeric punctuation while retaining word boundaries.
6. **Whitespace Normalization:** Compresses duplicate whitespace and strips edges.

---

## 4. Machine Learning Model

### Vectorizer: TF-IDF (Term Frequency - Inverse Document Frequency)
- **N-gram Range:** `(1, 2)` (unigrams and bigrams to capture compound phrases like *"urgent wire"*, *"immediate transfer"*, *"hi team"*)
- **Max Features:** `2500`
- **Sublinear TF Scaling:** Enabled (`sublinear_tf=True`) to dampen the effect of repetitive words
- **Min Document Frequency:** `1`
- **Stop Words:** English stop words removed

### Classifier: Logistic Regression
- **Algorithm:** L2-regularized Logistic Regression
- **Regularization Strength ($C$):** `1.5`
- **Solver:** `lbfgs`
- **Max Iterations:** `1000`
- **Random Seed:** `42` (ensures exact reproducibility across training runs)

---

## 5. Train/Test Split & Model Evaluation

- **Split Ratio:** 80% Train (64 samples), 20% Test (16 samples)
- **Sampling Strategy:** Stratified sampling preserving class balance (8 legitimate, 8 phishing in test split)
- **Random State:** `42`

### Measured Metrics (Tested on Unseen Test Split)

| Metric | Overall Value | Phishing Class (label = 1) | Legitimate Class (label = 0) |
| :--- | :--- | :--- | :--- |
| **Accuracy** | **93.75%** | — | — |
| **Precision** | **94.44%** (Macro) | **88.89%** | **100.00%** |
| **Recall** | **93.75%** (Macro) | **100.00%** | **87.50%** |
| **F1-Score** | **93.73%** (Macro) | **94.12%** | **93.33%** |

### Confusion Matrix
```
                 Predicted Legitimate (0)    Predicted Phishing (1)
Actual Legit (0)            7                          1  (False Positive)
Actual Phish (1)            0                          8  (True Positive)
```

> **Note:** Zero false negatives on the test split ensures critical threats are not silently missed by the linguistic model.

### Top Phishing Features (Model Coefficients)
1. `url_token` (+0.7115)
2. `urgent` (+0.6166)
3. `immediately` (+0.5982)
4. `wire` (+0.5628)
5. `account` (+0.5149)
6. `sign` (+0.4781)
7. `immediate` (+0.4672)

### Top Legitimate Features (Negative Coefficients)
1. `hi` (-0.5306)
2. `team` (-0.4807)
3. `scheduled` (-0.4092)
4. `internal` (-0.4090)
5. `cloud` (-0.3365)
6. `review` (-0.3053)

*Metrics and coefficients are recorded in [`ml/model/evaluation_metrics.json`](file:///d:/SIH%202026/maverick/ml/model/evaluation_metrics.json).*

---

## 6. Prediction API & Endpoints

The model is exposed via FastAPI and Node.js backend proxy:

### Endpoints
- **FastAPI Microservice:** `POST http://127.0.0.1:8000/predict`
- **Backend Gateway Proxy:** `POST http://localhost:5000/api/ml/predict` and `POST http://localhost:5000/predict`
- **Health Check:** `GET http://127.0.0.1:8000/health`

### Request Schema
```json
{
  "text": "email subject and body text to evaluate"
}
```

### Response Schema
```json
{
  "prediction": "phishing",
  "phishing_probability": 0.94,
  "legitimate_probability": 0.06,
  "confidence": 0.94,
  "model": "TF-IDF + Logistic Regression",
  "top_features": [
    {
      "term": "immediately",
      "weight": 0.5982,
      "tfidf": 0.2012,
      "impact": 0.1203,
      "indicator": "PHISHING"
    },
    {
      "term": "urgent",
      "weight": 0.6166,
      "tfidf": 0.1945,
      "impact": 0.1199,
      "indicator": "PHISHING"
    }
  ],
  "status": "SUCCESS"
}
```

---

## 7. Error Handling & Resilience

MAVERICK adheres to strict operational resilience rules:

1. **Empty / Blank Input:** Returns `prediction: "UNAVAILABLE"` with `status: "EMPTY_INPUT"`.
2. **Short Input:** Evaluated cleanly without division-by-zero or shape mismatch errors.
3. **Malformed JSON / Non-string Input:** Returns HTTP 422 / safe error JSON.
4. **Service Unreachable / Offline:**
   - When the ML microservice is offline, MAVERICK sets `prediction: "UNAVAILABLE"` and `phishing_probability: null`.
   - **Zero predictions are fabricated.**
   - Evidence Fusion allocates **0 points** out of 25 to Layer 1.
   - The remaining forensic layers (SPF/DKIM/DMARC, Attachment Forensics, GeoLocation, Threat Intelligence) proceed unimpeded to compute the final risk score.

---

## 8. Limitations & Boundary Conditions

- **Dataset Dependency:** Model performance directly reflects the scope and balance of the training dataset. An expanded production dataset will improve generalization on nuanced enterprise-specific communications.
- **Adversarial Obfuscation:** Attackers using zero-width spaces, leetspeak, or image-only lures may evade pure NLP models; MAVERICK mitigates this through multi-layer evidence fusion with header forensics and optical/attachment layers.
- **Non-Absolute Proof:** All ML outputs are probabilistic indicators and must be corroborated by cryptographic (DKIM/SPF) and IOC forensic proof before automated containment actions are triggered.

---

## 9. Developer Commands

```bash
# Install Python dependencies
pip install -r ml/requirements.txt

# Retrain the model and regenerate evaluation metrics
python ml/train.py
# or: npm run train

# Start the FastAPI ML microservice on port 8000
python ml/predict.py --serve --port 8000
# or: npm run ml

# Run single CLI inference
python ml/predict.py --text "Urgent wire transfer required"

# Run automated tests
npm test
```
