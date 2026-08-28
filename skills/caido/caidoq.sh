#!/usr/bin/env zsh
# caidoq.sh — one-shot GraphQL client for a local Caido instance.
# Usage:
#   caidoq.sh '<graphql query>'                    # query string as arg
#   echo '<graphql query>' | caidoq.sh             # query via stdin
#   caidoq.sh '<query>' '{"var":"value"}'          # with variables JSON
#
# Env / token:
#   CAIDO_URL   (default http://127.0.0.1:8080)
#   CAIDO_TOKEN (or token cached at ~/.config/caido/token)
set -euo pipefail

CAIDO_URL="${CAIDO_URL:-http://127.0.0.1:8080}"
TOKEN="${CAIDO_TOKEN:-}"

if [[ -z "$TOKEN" && -f "$HOME/.config/caido/token" ]]; then
  TOKEN="$(<"$HOME/.config/caido/token")"
fi

QUERY="${1:-}"
[[ -z "$QUERY" ]] && QUERY="$(cat)"
VARS="${2:-null}"

AUTH=()
if [[ -n "$TOKEN" ]]; then
  AUTH=(-H "Authorization: Bearer $TOKEN")
fi

exec curl -s --max-time 30 "$CAIDO_URL/graphql" \
  -H 'Content-Type: application/json' \
  "${AUTH[@]}" \
  -d "$(jq -n --arg q "$QUERY" --argjson v "$VARS" '{query:$q, variables:$v}')"
