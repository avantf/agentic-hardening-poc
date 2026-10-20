# Build context: testbed/services
FROM python:3.12-slim

RUN pip install --no-cache-dir flask==3.0.3

WORKDIR /app
COPY common/testbed_status.py storage-service/app.py ./
COPY storage-service/entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh && mkdir -p /data/records /data/backups

EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=3s --retries=10 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)"
ENTRYPOINT ["/entrypoint.sh"]
