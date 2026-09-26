#!/bin/sh
# Comprueba que la máquina puede ejecutar Tamandua y dice cómo arreglar lo que falte.
# Uso: make doctor   (o sh scripts/doctor.sh)
set -u

ok=0; warn=0; fail=0
pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; ok=$((ok + 1)); }
note() { printf '  \033[33m!\033[0m %s\n      → %s\n' "$1" "$2"; warn=$((warn + 1)); }
bad()  { printf '  \033[31m✗\033[0m %s\n      → %s\n' "$1" "$2"; fail=$((fail + 1)); }

version_ge() { # ¿$1 >= $2? comparando números separados por puntos
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -t. -k1,1n -k2,2n -k3,3n | head -n1)" = "$2" ]
}

echo "Tamandua · comprobación del entorno"
echo

echo "Herramientas"
if command -v docker >/dev/null 2>&1; then
  pass "docker instalado ($(docker --version 2>/dev/null | sed 's/Docker version //; s/,.*//'))"
  if docker info >/dev/null 2>&1; then
    server=$(docker version --format '{{.Server.Version}}' 2>/dev/null)
    if version_ge "${server:-0}" 24.0.0; then pass "demonio de Docker en marcha ($server)"; else bad "Docker Engine $server es antiguo" "Actualiza a Docker Engine 24 o superior."; fi
  else
    bad "el demonio de Docker no responde" "Arranca Docker Desktop/OrbStack, o 'sudo systemctl start docker' en Linux (y añade tu usuario al grupo docker)."
  fi
  compose=$(docker compose version --short 2>/dev/null | sed 's/^v//')
  if [ -z "$compose" ]; then
    bad "falta docker compose (v2)" "Instala el plugin: https://docs.docker.com/compose/install/"
  elif version_ge "$compose" 2.24.0; then
    pass "docker compose $compose"
  else
    bad "docker compose $compose es antiguo" "Hace falta 2.24 o superior (env_file opcional)."
  fi
else
  bad "docker no está instalado" "https://docs.docker.com/get-docker/ (o OrbStack en macOS)."
fi
if command -v git >/dev/null 2>&1; then pass "git instalado"; else note "git no está instalado" "Solo hace falta para actualizar con 'make update'."; fi
if command -v make >/dev/null 2>&1; then pass "make instalado"; fi

echo
echo "Sistema"
arch=$(uname -m)
case "$arch" in
  x86_64|amd64|arm64|aarch64) pass "arquitectura $arch" ;;
  *) bad "arquitectura $arch no soportada" "Solo amd64 y arm64." ;;
esac
free_kb=$(df -Pk . 2>/dev/null | awk 'NR==2 {print $4}')
if [ -n "${free_kb:-}" ]; then
  free_gb=$((free_kb / 1024 / 1024))
  if [ "$free_gb" -ge 8 ]; then pass "espacio libre: ${free_gb} GB"; else note "solo ${free_gb} GB libres" "Se recomiendan 8 GB (imágenes, bases de Trivy y Grype, copia de NVD)."; fi
fi

echo
echo "Configuración"
if [ -f .env ]; then pass ".env presente"; else note "no hay .env" "'make setup' lo crea desde .env.example con tu UID/GID."; fi
for dir in data config; do
  if [ -d "$dir" ]; then
    if [ -w "$dir" ]; then pass "$dir/ existe y es tuya"; else bad "$dir/ no es escribible por ti" "sudo chown -R $(id -u):$(id -g) $dir"; fi
  else
    note "$dir/ no existe" "'make setup' la crea (si la crea Docker, será de root)."
  fi
done
if [ -f .env ]; then
  uid=$(sed -n 's/^TAMANDUA_UID=//p' .env | tail -n1); gid=$(sed -n 's/^TAMANDUA_GID=//p' .env | tail -n1)
  if [ "${uid:-}" = "$(id -u)" ] && [ "${gid:-}" = "$(id -g)" ]; then pass "TAMANDUA_UID/GID coinciden con tu usuario"; else note "TAMANDUA_UID/GID de .env ($uid/$gid) no son los tuyos ($(id -u)/$(id -g))" "Corrígelos en .env o borra .env y ejecuta 'make setup'."; fi
  port=$(sed -n 's/^TAMANDUA_HOST_PORT=//p' .env | tail -n1)
fi
port=${port:-8766}
if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -qx tamandua; then
  pass "Tamandua ya está en marcha (puerto $port)"
elif (command -v nc >/dev/null 2>&1 && nc -z 127.0.0.1 "$port" 2>/dev/null); then
  bad "el puerto $port está ocupado por otro programa" "Cambia TAMANDUA_HOST_PORT, TAMANDUA_PUBLIC_URL y TAMANDUA_ALLOWED_ORIGINS en .env."
else
  pass "puerto $port libre"
fi

echo
echo "Motores de análisis"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  for image in $(sed -n 's/.*"image": "\([^"]*\)".*/\1/p' tamandua/modules/scanning/engines.py); do
    if docker image inspect "$image" >/dev/null 2>&1; then pass "$image"; else note "falta $image" "'make build' construye Opengrep y 'make engines' descarga Trivy, OSV-Scanner, Gitleaks, Grype, Checkov y zizmor (si no, se bajan en el primer análisis)."; fi
  done
fi

echo
printf 'Resultado: %s correctos, %s avisos, %s errores\n' "$ok" "$warn" "$fail"
[ "$fail" -eq 0 ]
