#!/bin/sh
set -eu

case "$(echo "${SSH_PASSWORD_AUTH:-no}" | tr '[:upper:]' '[:lower:]')" in
  yes|true|1) value=yes ;;
  *)          value=no ;;
esac

# Single authoritative PasswordAuthentication line in sshd_config; drop any
# override from sshd_config.d so the main file is what the baseline checks.
sed -i '/^[#[:space:]]*PasswordAuthentication[[:space:]]/Id' /etc/ssh/sshd_config
echo "PasswordAuthentication $value" >> /etc/ssh/sshd_config
if [ -d /etc/ssh/sshd_config.d ]; then
  find /etc/ssh/sshd_config.d -name '*.conf' -exec sed -i '/^[[:space:]]*PasswordAuthentication[[:space:]]/Id' {} +
fi

mkdir -p /run/sshd
ssh-keygen -A >/dev/null
/usr/sbin/sshd -t
/usr/sbin/sshd

exec python3 /app/status_server.py
