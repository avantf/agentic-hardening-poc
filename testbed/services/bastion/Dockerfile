# Build context: testbed/services
FROM ubuntu:24.04

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server python3 curl procps \
 && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_*

WORKDIR /app
COPY common/testbed_status.py bastion/status_server.py ./
COPY bastion/entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

EXPOSE 22 8080
HEALTHCHECK --interval=5s --timeout=3s --retries=10 \
  CMD curl -fsS http://127.0.0.1:8080/health || exit 1
ENTRYPOINT ["/entrypoint.sh"]
