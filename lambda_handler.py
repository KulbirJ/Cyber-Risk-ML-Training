"""
AWS Lambda handler — wraps the FastAPI app via Mangum.

The ASGI adapter translates API Gateway events into ASGI requests
and returns the FastAPI response as an API Gateway response.
"""
from mangum import Mangum
from serve_risk_model import app

handler = Mangum(app, lifespan="off")
