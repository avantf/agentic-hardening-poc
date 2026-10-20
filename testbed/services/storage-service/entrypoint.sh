#!/bin/sh
set -eu

CONFIG_PATH="${CONFIG_PATH:-/etc/storage/storage.conf}"
mkdir -p "$(dirname "$CONFIG_PATH")"
if [ ! -f "$CONFIG_PATH" ]; then
  printf 'data_dir = /data/records\nbackup_dir = /data/backups\nreplication_secret = testbed-only\n' > "$CONFIG_PATH"
fi
chown root:root "$CONFIG_PATH"
chmod "${CONFIG_FILE_MODE:-0640}" "$CONFIG_PATH"

exec python app.py
