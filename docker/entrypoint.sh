#!/bin/sh
set -eu

CONFIG="${CONFIG_PATH:-/app/config.yaml}"
BIN="/app/os-cve-cache"

# Ensure schema exists before serve/query/fetch.
"$BIN" init-db --config "$CONFIG"

if [ "$#" -eq 0 ]; then
  set -- serve
fi

cmd="$1"
shift

case "$cmd" in
  serve)
    addr="${ADDR:-:8080}"
    exec "$BIN" serve --config "$CONFIG" --addr "$addr" "$@"
    ;;
  fetch|query|init-db)
    exec "$BIN" "$cmd" --config "$CONFIG" "$@"
    ;;
  *)
    exec "$BIN" "$cmd" "$@"
    ;;
esac
