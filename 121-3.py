"""
MAVERICK — Environment and Artifacts Utility (121-3)
"""

import os

def check_model_artifacts(model_dir: str = "ml/model") -> bool:
    vec_path = os.path.join(model_dir, "vectorizer.pkl")
    model_path = os.path.join(model_dir, "phishing_model.pkl")
    return os.path.exists(vec_path) and os.path.exists(model_path)

if __name__ == "__main__":
    status = check_model_artifacts()
    print(f"Model artifacts available: {status}")
