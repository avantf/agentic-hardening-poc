# Build context: testbed/services
FROM python:3.12-slim

# Overridable to inject a known-vulnerable version (see config/drift_scenarios.yaml).
ARG WERKZEUG_VERSION=3.0.6
RUN pip install --no-cache-dir flask==3.0.3 werkzeug==${WERKZEUG_VERSION}

WORKDIR /app
COPY common/testbed_status.py vuln-web/app.py ./

EXPOSE 8080 9000
HEALTHCHECK --interval=5s --timeout=3s --retries=10 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)"
CMD ["python", "app.py"]
