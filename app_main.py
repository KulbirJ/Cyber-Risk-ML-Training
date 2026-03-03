# app_main.py
"""
Import point for uvicorn.
This allows us to run: uvicorn app_main:app --reload
"""

from serve_risk_model import app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
