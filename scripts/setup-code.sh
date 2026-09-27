#!/bin/sh
# Prints the code to create the first administrator, while there is none. Usage: make setup-code
# The code lives in the database (sealed), so any instance of the API accepts it.
set -eu

if output=$(docker compose exec -T api python -m tamandua --data-dir /data setup-code 2>/dev/null); then
  echo "$output"
else
  echo "The app is not answering yet: try again in a moment (make setup-code), or look at make logs."
fi
