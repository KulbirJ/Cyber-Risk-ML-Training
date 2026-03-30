# ML Risk Scoring Microservice — Lambda container image
#
# Serves the cyber-risk XGBoost v3 model (28 features, 3-tier enrichment)
# behind API Gateway via the Mangum adapter.
#
# Build:  docker build -t cyber-risk-ml .
# Local:  docker run -p 8000:8080 --env-file .env cyber-risk-ml

FROM public.ecr.aws/lambda/python:3.11

# Install dependencies
COPY requirements.txt ${LAMBDA_TASK_ROOT}/
RUN pip install --no-cache-dir -r ${LAMBDA_TASK_ROOT}/requirements.txt

# Copy application code + model artifacts
COPY serve_risk_model.py ${LAMBDA_TASK_ROOT}/
COPY lambda_handler.py ${LAMBDA_TASK_ROOT}/
COPY cyber_risk_model_v1.json ${LAMBDA_TASK_ROOT}/
COPY cyber_risk_model_v3.json ${LAMBDA_TASK_ROOT}/
COPY cyber_risk_severity_model_v3.json ${LAMBDA_TASK_ROOT}/

# Mangum handler entrypoint
CMD ["lambda_handler.handler"]
