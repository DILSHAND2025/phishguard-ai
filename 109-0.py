"""
MAVERICK — ML Service Runner (109-0)
"""

import sys
import os
import uvicorn

REPO_ROOT = os.path.abspath(os.path.dirname(__file__))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from ml.predict import app

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
