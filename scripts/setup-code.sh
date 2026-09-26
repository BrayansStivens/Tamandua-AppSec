#!/bin/sh
# Prints the code to create the first administrator, while there is none. Usage: make setup-code
# The question goes through the api container itself: it works the same with a published port or behind Caddy.
set -eu

url=${1:-}
code=$(docker compose logs api 2>/dev/null | grep -oE '(^|[| ])[A-HJ-NP-Z2-9]{4}(-[A-HJ-NP-Z2-9]{4}){2} *$' | tail -n1 | tr -d ' |')
pending=$(docker compose exec -T api python -c "
import json, os, urllib.parse as p, urllib.request as r
host = p.urlsplit((os.environ.get('TAMANDUA_ALLOWED_ORIGINS') or 'http://127.0.0.1:8766').split(',')[0].strip()).netloc
request = r.Request('http://127.0.0.1:8766/api/auth/session', headers={'Host': host})
print(json.load(r.urlopen(request, timeout=5)).get('setup_required') is True)
" 2>/dev/null || echo unknown)

if [ "$pending" = "True" ] && [ -n "$code" ]; then
  echo "Setup code: $code  (create the administrator at $url)"
elif [ "$pending" = "False" ]; then
  echo "An administrator already exists: sign in with your user."
else
  echo "The app is not answering yet: try again in a moment (make setup-code), or look at make logs."
fi
