"""
MAVERICK — FastAPI ML Microservice Deployment & Endpoint Test Suite
Smart India Hackathon 2026
"""

import os
import sys
import unittest
from fastapi.testclient import TestClient

# Ensure repo root is on sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from ml.predict import app, load_artifacts, clean_text, predict_threat, VEC_PATH, MODEL_PATH


class TestMLService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        # Ensure artifacts are loaded
        cls.vectorizer, cls.model = load_artifacts()

    def test_01_root_endpoint(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get("service"), "MAVERICK ML Inference Engine")
        self.assertIn("health", data.get("endpoints", {}))
        self.assertIn("predict", data.get("endpoints", {}))

    def test_02_health_endpoint_healthy(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get("status"), "healthy")
        self.assertTrue(data.get("model_loaded"))
        self.assertEqual(data.get("model_type"), "TF-IDF + Logistic Regression")
        self.assertIsInstance(data.get("vocabulary_size"), int)
        self.assertGreater(data.get("vocabulary_size"), 0)
        self.assertEqual(data.get("vectorizer_path"), VEC_PATH)
        self.assertEqual(data.get("model_path"), MODEL_PATH)

    def test_03_predict_legitimate_email(self):
        legit_text = (
            "Dear team, please find attached the weekly project status report "
            "for our review meeting scheduled for tomorrow afternoon. Thanks, Alice."
        )
        response = self.client.post("/predict", json={"text": legit_text})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get("status"), "SUCCESS")
        self.assertEqual(data.get("prediction"), "legitimate")
        self.assertLess(data.get("phishing_probability"), 0.5)
        self.assertGreater(data.get("legitimate_probability"), 0.5)
        self.assertEqual(data.get("model"), "TF-IDF + Logistic Regression")
        self.assertIsNotNone(data.get("confidence"))

    def test_04_predict_phishing_email(self):
        phish_text = (
            "URGENT: Immediate wire transfer authorization required immediately. "
            "Statutory allocation directive issued. Verify your banking credentials "
            "at http://secure-portal-auth.online or account will be suspended."
        )
        response = self.client.post("/predict", json={"text": phish_text})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get("status"), "SUCCESS")
        self.assertEqual(data.get("prediction"), "phishing")
        self.assertGreaterEqual(data.get("phishing_probability"), 0.5)
        self.assertLessEqual(data.get("legitimate_probability"), 0.5)
        self.assertEqual(data.get("model"), "TF-IDF + Logistic Regression")
        self.assertIsInstance(data.get("top_features"), list)
        self.assertGreater(len(data.get("top_features")), 0)
        terms = [item["term"] for item in data.get("top_features")]
        # Check presence of salient tokens
        self.assertTrue(any(t in ["urgent", "immediately", "wire", "account", "transfer"] for t in terms))

    def test_05_predict_short_text(self):
        response = self.client.post("/predict", json={"text": "OK"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get("status"), "SUCCESS")
        self.assertEqual(data.get("prediction"), "legitimate")
        self.assertIn("short", data.get("note", "").lower())

    def test_06_predict_empty_text(self):
        response = self.client.post("/predict", json={"text": ""})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get("status"), "SUCCESS")
        self.assertEqual(data.get("prediction"), "legitimate")

    def test_07_clean_text(self):
        raw = "Check <b>this</b> https://example.com/login and email user@gov.in NOW!"
        cleaned = clean_text(raw)
        self.assertNotIn("<b>", cleaned)
        self.assertNotIn("https://example.com/login", cleaned)
        self.assertIn("url_token", cleaned)
        self.assertIn("email_token", cleaned)
        self.assertNotIn("user@gov.in", cleaned)
        self.assertTrue(cleaned.islower())

    def test_08_health_endpoint_failure_reporting(self):
        import ml.predict as predict_module
        original_model = predict_module._model
        original_path = predict_module.MODEL_PATH
        try:
            # Point to a nonexistent model path
            predict_module._model = None
            predict_module.MODEL_PATH = "/tmp/nonexistent_model_test.pkl"
            response = self.client.get("/health")
            self.assertEqual(response.status_code, 503)
            data = response.json()
            detail = data.get("detail", {})
            self.assertEqual(detail.get("status"), "unhealthy")
            self.assertFalse(detail.get("model_loaded"))
        finally:
            # Restore model and path
            predict_module.MODEL_PATH = original_path
            predict_module._model = original_model
            predict_module.load_artifacts(force_reload=True)

    def test_09_model_loading_cwd_independence(self):
        # Verify that loading artifacts succeeds regardless of CWD
        vec, mdl = load_artifacts()
        self.assertIsNotNone(vec)
        self.assertIsNotNone(mdl)
        self.assertTrue(os.path.isabs(VEC_PATH))
        self.assertTrue(os.path.isabs(MODEL_PATH))


if __name__ == "__main__":
    unittest.main(verbosity=2)
