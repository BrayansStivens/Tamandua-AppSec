#!/bin/sh
# Checks that this machine can run Tamandua and says how to fix what's missing.
# Usage: make doctor   (or sh scripts/doctor.sh)
set -u

ok=0; warn=0; fail=0
pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; ok=$((ok + 1)); }
note() { printf '  \033[33m!\033[0m %s\n      → %s\n' "$1" "$2"; warn=$((warn + 1)); }
bad()  { printf '  \033[31m✗\033[0m %s\n      → %s\n' "$1" "$2"; fail=$((fail + 1)); }

version_ge() { # $1 >= $2, comparing dot-separated numbers
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -t. -k1,1n -k2,2n -k3,3n | head -n1)" = "$2" ]
}

echo "Tamandua · environment check"
echo

echo "Tools"
if command -v docker >/dev/null 2>&1; then
  pass "docker installed ($(docker --version 2>/dev/null | sed 's/Docker version //; s/,.*//'))"
  if docker info >/dev/null 2>&1; then
    server=$(docker version --format '{{.Server.Version}}' 2>/dev/null)
    if version_ge "${server:-0}" 24.0.0; then pass "Docker daemon running ($server)"; else bad "Docker Engine $server is too old" "Upgrade to Docker Engine 24 or later."; fi
  else
    bad "the Docker daemon is not responding" "Start Docker Desktop/OrbStack, or 'sudo systemctl start docker' on Linux (and add your user to the docker group)."
  fi
  compose=$(docker compose version --short 2>/dev/null | sed 's/^v//')
  if [ -z "$compose" ]; then
    bad "docker compose (v2) is missing" "Install the plugin: https://docs.docker.com/compose/install/"
  elif version_ge "$compose" 2.24.0; then
    pass "docker compose $compose"
  else
    bad "docker compose $compose is too old" "2.24 or later is required (optional env_file)."
  fi
else
  bad "docker is not installed" "https://docs.docker.com/get-docker/ (or OrbStack on macOS)."
fi
if command -v git >/dev/null 2>&1; then pass "git installed"; else note "git is not installed" "Only needed to update with 'make update'."; fi
if command -v make >/dev/null 2>&1; then pass "make installed"; fi

echo
echo "System"
arch=$(uname -m)
case "$arch" in
  x86_64|amd64|arm64|aarch64) pass "architecture $arch" ;;
  *) bad "architecture $arch is not supported" "Only amd64 and arm64." ;;
esac
free_kb=$(df -Pk . 2>/dev/null | awk 'NR==2 {print $4}')
if [ -n "${free_kb:-}" ]; then
  free_gb=$((free_kb / 1024 / 1024))
  if [ "$free_gb" -ge 8 ]; then pass "free space: ${free_gb} GB"; else note "only ${free_gb} GB free" "8 GB recommended (images, Trivy and Grype databases, NVD copy)."; fi
fi

echo
echo "Configuration"
if [ -f .env ]; then pass ".env present"; else note "no .env" "'make setup' creates it from .env.example with your UID/GID."; fi
for dir in data config; do
  if [ -d "$dir" ]; then
    if [ -w "$dir" ]; then pass "$dir/ exists and is yours"; else bad "$dir/ is not writable by you" "sudo chown -R $(id -u):$(id -g) $dir"; fi
  else
    note "$dir/ does not exist" "'make setup' creates it (if Docker creates it, root will own it)."
  fi
done
if [ -f .env ]; then
  uid=$(sed -n 's/^TAMANDUA_UID=//p' .env | tail -n1); gid=$(sed -n 's/^TAMANDUA_GID=//p' .env | tail -n1)
  if [ "${uid:-}" = "$(id -u)" ] && [ "${gid:-}" = "$(id -g)" ]; then pass "TAMANDUA_UID/GID match your user"; else note "TAMANDUA_UID/GID in .env ($uid/$gid) are not yours ($(id -u)/$(id -g))" "Fix them in .env, or delete .env and run 'make setup'."; fi
  port=$(sed -n 's/^TAMANDUA_HOST_PORT=//p' .env | tail -n1)
fi
port=${port:-8766}
if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -qx tamandua; then
  pass "Tamandua is already running (port $port)"
elif (command -v nc >/dev/null 2>&1 && nc -z 127.0.0.1 "$port" 2>/dev/null); then
  bad "port $port is in use by another program" "Change TAMANDUA_HOST_PORT, TAMANDUA_PUBLIC_URL and TAMANDUA_ALLOWED_ORIGINS in .env."
else
  pass "port $port free"
fi

echo
echo "Analysis engines"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  for image in $(sed -n 's/.*"image": "\([^"]*\)".*/\1/p' tamandua/modules/scanning/engines.py); do
    if docker image inspect "$image" >/dev/null 2>&1; then pass "$image"; else note "missing $image" "'make build' builds Opengrep and 'make engines' pulls Trivy, OSV-Scanner, Gitleaks, Grype, Checkov and zizmor (otherwise they are pulled on the first scan)."; fi
  done
fi

echo
printf 'Result: %s passed, %s warnings, %s errors\n' "$ok" "$warn" "$fail"
[ "$fail" -eq 0 ]
