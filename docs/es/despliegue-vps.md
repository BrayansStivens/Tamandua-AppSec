[English](../deploy-vps.md) · Español

# Desplegar en un VPS

Esta guía deja Tamandua en un servidor propio (Hetzner, DigitalOcean, Hostinger, OVH o cualquier VPS con Docker), con tu dominio, HTTPS, copias de seguridad y monitorización. Para usarlo en tu portátil sigue bastando `make up`: mira [instalacion.md](instalacion.md).

Con un servidor recién creado y un registro DNS que ya apunte a él, son cuatro comandos:

```bash
git clone https://github.com/BrayansStivens/appsec-agent.git && cd appsec-agent
git checkout v0.9                                   # la versión que quieras (ver Actualizar)
make setup DOMAIN=tamandua.example.com PREBUILT=1   # HTTPS con Caddy + imágenes publicadas
make up                                             # muestra https://tamandua.example.com y el código de configuración
```

El resto de la página cuenta qué preparar antes y qué hacer después.

## Cómo queda montado

```
internet ──443/80──▶ caddy ──red edge──▶ api (panel + API, sin puerto publicado)
                                            │
                                   red default ── postgres (sin puerto publicado)
                                            │
                                          worker ──docker.sock──▶ contenedores de los motores (uno por paso del análisis)
```

- `compose.prod.yaml` añade **Caddy**: pide y renueva el certificado de tu dominio (Let's Encrypt, y ZeroSSL si falla), redirige HTTP a HTTPS y es lo único que publica puertos. La api no publica ninguno; `TAMANDUA_PUBLIC_URL` y `TAMANDUA_ALLOWED_ORIGINS` pasan a ser `https://<dominio>`.
- `compose.images.yaml` (con `PREBUILT`) usa las imágenes publicadas en el registro de GitHub en lugar de construirlas en el servidor. Son multiarquitectura (amd64 y arm64), llevan SBOM y procedencia, y van firmadas con cosign.
- `make setup DOMAIN=…` deja los dos overlays en `COMPOSE_FILE` dentro de `.env`: así los usan todos los comandos `make` y también `docker compose` a secas.

## 1. Elegir el servidor

| | Mínimo | Holgado |
| --- | --- | --- |
| CPU | 2 vCPU | 4 vCPU |
| Memoria | 4 GB (+2 GB de swap) | 8 GB |
| Disco | 40 GB SSD | 80 GB SSD |
| Arquitectura | amd64 o arm64 (Hetzner CAX, Graviton, Ampere) | |

En qué se va: cada análisis ejecuta un motor a la vez, con un tope de 2 CPU y 3 GB de memoria; la app y PostgreSQL ocupan unos 400 MB en reposo. En disco, las imágenes de los motores suman unos 2 GB, la base de Trivy ~1,3 GB, la de Grype ~2,1 GB (solo si analizas imágenes de contenedor), la copia local de NVD ~0,7 GB, y cada análisis guarda una instantánea del repositorio mientras corre. Deja sitio para las copias si pasan por el mismo disco antes de salir del servidor.

Usa un **servidor dedicado** a Tamandua, no uno compartido con otras aplicaciones ni con otras personas: mira [Endurecimiento](#endurecimiento).

## 2. Preparar el sistema

En Ubuntu 24.04 (en Debian es igual, cambiando `ubuntu` por `debian` en las URL de Docker). Como root, solo la primera vez:

```bash
# Un usuario para Tamandua, con tu clave SSH; después, nunca más entres como root.
adduser --disabled-password --gecos "" tamandua
mkdir -p /home/tamandua/.ssh && cp ~/.ssh/authorized_keys /home/tamandua/.ssh/
chown -R tamandua:tamandua /home/tamandua/.ssh && chmod 700 /home/tamandua/.ssh
usermod -aG sudo tamandua && passwd tamandua   # contraseña de sudo para el mantenimiento

# SSH: solo con clave y sin root. Un drop-in que se lee primero gana al de la imagen del proveedor (50-cloud-init.conf).
printf 'PasswordAuthentication no\nPermitRootLogin no\n' > /etc/ssh/sshd_config.d/10-tamandua.conf
sshd -t && systemctl restart ssh

# Actualizaciones de seguridad automáticas.
apt-get update && apt-get install -y unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades

# Cortafuegos: solo SSH, HTTP y HTTPS.
ufw default deny incoming && ufw default allow outgoing
ufw allow 22/tcp && ufw allow 80/tcp && ufw allow 443/tcp && ufw allow 443/udp
ufw enable
```

Docker Engine, desde el repositorio oficial de Docker (el paquete `docker.io` de la distribución va con retraso y no trae Compose v2):

```bash
apt-get install -y ca-certificates curl make git
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" > /etc/apt/sources.list.d/docker.list
apt-get update && apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
usermod -aG docker tamandua
```

Pertenecer al grupo `docker` equivale a ser root en esta máquina: dáselo solo a quien administre el servidor.

**Docker y ufw.** Los puertos que publica Docker se saltan las reglas de ufw. Por eso Tamandua solo publica el 80 y el 443 (Caddy) y nada más: PostgreSQL y la API viven en redes internas. No añadas `ports:` a otros servicios. Si tu proveedor tiene cortafuegos en la nube (Hetzner Cloud Firewall, Cloud Firewalls de DigitalOcean, el cortafuegos del VPS de Hostinger), aplica ahí la misma regla: entrada por 22, 80 y 443; salida, todo.

## 3. Apuntar el dominio

Crea un registro **A** (y **AAAA** si el servidor tiene IPv6) con el nombre que vayas a usar, por ejemplo `tamandua.example.com`, hacia la IP pública del servidor. Compruébalo antes de arrancar, porque Caddy pide el certificado nada más empezar:

```bash
dig +short tamandua.example.com     # tiene que devolver la IP del servidor
```

Si quieres, un registro CAA `0 issue "letsencrypt.org"` limita quién puede emitir certificados para ese nombre. Si lo pones, permite también `sectigo.com` (ZeroSSL, la alternativa de Caddy) para no dejarle una sola opción.

## 4. Configurar

Con el usuario `tamandua`:

```bash
git clone https://github.com/BrayansStivens/appsec-agent.git && cd appsec-agent
git checkout v0.9
make setup DOMAIN=tamandua.example.com PREBUILT=1
make doctor
```

`make setup` crea `.env` con tu UID/GID y una contraseña aleatoria para la base de datos; en modo servidor escribe además:

| Variable | Valor | Para qué |
| --- | --- | --- |
| `TAMANDUA_DOMAIN` | tu dominio | Certificado y sitio de Caddy. |
| `TAMANDUA_PUBLIC_URL` / `TAMANDUA_ALLOWED_ORIGINS` | `https://<dominio>` | Cookies `Secure`, HSTS, CSRF y `Host` permitido. El overlay los deriva del dominio de todas formas. |
| `COMPOSE_FILE` | `compose.yaml:compose.prod.yaml[:compose.images.yaml]` | Que todos los comandos usen los overlays. |
| `TAMANDUA_IMAGE` | `ghcr.io/brayansstivens/tamandua` | Solo con `PREBUILT`. Para un fork: `PREBUILT=ghcr.io/tu-usuario/tamandua`. |
| `TAMANDUA_METRICS_TOKEN` | 64 caracteres aleatorios | Activa `/api/metrics` (mira [Monitorización](#monitorización)). |

Sin `PREBUILT`, el servidor construye las imágenes a partir del código (unos minutos, y más memoria mientras tanto). Las dos opciones ejecutan el mismo código.

Conviene revisar en `.env` antes del primer arranque (todas en [configuracion.md](configuracion.md)):

- `TAMANDUA_REQUIRE_TOTP=all`: segundo factor para todo el mundo, no solo para administradores. Recomendado si está en internet.
- `TAMANDUA_DEFAULT_LOCALE=es` si tu equipo trabaja en español (comentarios en PRs, avisos, informes).
- `TAMANDUA_NVD_API_KEY`: la copia de CVE se descarga en minutos en vez de horas.
- `TAMANDUA_MASTER_KEY`: por defecto la clave del almacén se genera en `config/master.key`. Si la defines aquí (o desde tu gestor de secretos), guarda una copia aparte: ya no irá en las copias de `config/`.
- `COMPOSE_PROFILES=backup`: copias programadas (mira [Copias de seguridad](#copias-de-seguridad)).

Guarda una copia de `.env` en tu gestor de contraseñas: contiene la contraseña de la base de datos, el token de métricas y, si la pusiste, la clave maestra.

## 5. Arrancar y crear el administrador

Con las imágenes publicadas, comprueba antes sus firmas (con [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) instalado):

```bash
make verify-images    # Signed by BrayansStivens/appsec-agent: ghcr.io/brayansstivens/tamandua:0.9 …
make up
```

`make up` descarga (o construye) las imágenes, arranca todo, espera a que el panel responda, descarga los motores y muestra la URL y el **código de configuración**. Abre `https://<dominio>`, introduce el código y crea tu usuario administrador; después activa el segundo factor en **Cuenta**. Si la página no carga, `make logs SERVICE=caddy` te dice si se emitió el certificado (lo habitual: el DNS todavía no apunta aquí, o el puerto 80 está cerrado).

El código solo aparece en la consola del servidor: quien abra la URL antes que tú no puede quedarse con la instancia. `make setup-code` lo vuelve a mostrar mientras no haya administrador.

## 6. GitHub App con dominio público

Sigue [github-app.md](github-app.md) con estos valores:

| Campo | Valor |
| --- | --- |
| Homepage URL | `https://<dominio>` |
| Setup URL | `https://<dominio>/oauth/callback`, con **Redirect on update** |
| Callback URL | vacío |
| Webhook | inactivo: Tamandua consulta los pull requests por su cuenta, GitHub nunca necesita llegar a tu servidor |

## Copias de seguridad

Una instancia son tres cosas: la **base de datos** (ejecuciones, hallazgos, triage, usuarios), **`config/`** (secretos cifrados y clave maestra) y **`.env`**. `data/` guarda cachés, logs y la clave que firma las sesiones: es útil, pero todo se regenera.

**Programadas, dentro de Compose.** Añade `COMPOSE_PROFILES=backup` a `.env` y ejecuta `make up`. El servicio `backup` escribe `backups/auto-<fecha>/` (database.dump, config.tgz, data.tgz) cada `TAMANDUA_BACKUP_INTERVAL_HOURS` (24) y borra sus propias copias con más de `TAMANDUA_BACKUP_KEEP_DAYS` días (14). No detiene la app (`pg_dump` ya es coherente por sí solo), recibe solo la contraseña de la base y monta `config/` y `data/` en solo lectura. Su healthcheck se pone en rojo si la última copia tiene más de dos intervalos. `TAMANDUA_BACKUP_DIR` las lleva a otra carpeta (por ejemplo, un volumen montado).

**Con cron, desde el host.** `make backup` hace lo mismo, pero detiene la API unos segundos para que `data/` también sea coherente; se niega si hay análisis en curso (cron lo reintenta al día siguiente):

```cron
30 3 * * * cd /home/tamandua/appsec-agent && make backup >> backups/cron.log 2>&1
```

**Fuera del servidor, siempre.** Una copia en el mismo disco no sobrevive al servidor. `config.tgz` lleva la clave maestra junto al almacén que abre, así que la copia externa tiene que ir **cifrada**. Por ejemplo con [restic](https://restic.net) a cualquier bucket compatible con S3 (Backblaze B2, Hetzner Object Storage, R2…):

```cron
0 4 * * * cd /home/tamandua/appsec-agent && restic backup backups/ --tag tamandua && restic forget --keep-daily 14 --keep-weekly 8 --prune
```

(`RESTIC_REPOSITORY`, `RESTIC_PASSWORD_FILE` y las credenciales del bucket en el entorno del crontab; la contraseña de restic, fuera del servidor.) En local basta con guardar unos días: `find backups -maxdepth 1 -name '20*' -mtime +7 -exec rm -rf {} +`.

**Restaurar.** Probado, en el mismo servidor o en uno nuevo:

```bash
make restore FROM=backups/<fecha> CONFIRM=restore
make up
```

Comprueba la copia antes de tocar nada, guarda el estado actual en `backups/pre-restore-<fecha>/` (así `make restore FROM=backups/pre-restore-<fecha> CONFIRM=restore` lo deshace), borra y recrea la base de datos a partir de `database.dump`, sustituye `config/` y extrae `data/`. En un **servidor nuevo**: prepáralo como arriba, recupera tu `.env`, clona la misma versión, `make setup`, copia la carpeta de la copia dentro de `backups/` y ejecuta los dos comandos. Restaura sobre la misma versión de Tamandua que hizo la copia o una más nueva: la app migra los datos hacia delante al arrancar, nunca hacia atrás. Da por hecho que `config/` está en el repositorio (el valor por defecto de `TAMANDUA_HOST_CONFIG_DIR`).

Si se pierde `config/master.key` (o cambia `TAMANDUA_MASTER_KEY`), los secretos no se pueden descifrar: tocaría volver a conectar la GitHub App y a introducir las claves de IA y de Jira. No se pierde nada más.

## Actualizar

```bash
git fetch --tags && git checkout v0.9.1    # o quédate en main y deja que make update lo traiga
make update
```

`make update` trae el código (`git pull --ff-only` si estás en una rama; en una etiqueta mantiene la versión que elegiste), hace una copia con `make backup` (si hay análisis en marcha se detiene: vuelve a intentarlo luego), descarga las imágenes nuevas y reinicia; la app migra la base de datos al arrancar. Lee las notas de la versión antes de saltar de versión menor. Para volver atrás: vuelve a la etiqueta anterior y `make restore FROM=backups/<la copia que hizo make update> CONFIRM=restore`, y después `make up`.

Con `PREBUILT`, la etiqueta de la imagen sigue al código que tienes (`tamandua/version.py`), así que los ficheros de compose, las reglas y las imágenes siempre coinciden. Para fijarla por digest, pon `TAMANDUA_IMAGE_TAG=0.9@sha256:…` en `.env`.

## Monitorización

**Healthchecks.** Docker vigila todos los servicios: `api` (`/api/health`), `worker` (su latido en la base de datos) y `backup`. `make status` los muestra, y si alguno cae se reinicia solo. Desde fuera, apunta un monitor de disponibilidad a `https://<dominio>/api/health`: responde `200 {"status": "ok"}` mientras la API esté arriba. A una persona con sesión iniciada le dice además `"status": "degraded"` cuando ningún worker ha dado señales de vida (no se analizaría nada), con cuántos workers hay y si llegan a Docker.

**Métricas.** `GET /api/metrics` en formato Prometheus, con `Authorization: Bearer <TAMANDUA_METRICS_TOKEN>` (desactivado mientras la variable esté vacía; entonces responde 404). Solo agregados: ni nombres de repositorios, ni identificadores, ni hallazgos.

| Métrica | Qué mide |
| --- | --- |
| `tamandua_jobs{status}` | Trabajos de la cola por estado (`queued`, `running`, `done`, `failed`). |
| `tamandua_jobs_oldest_queued_age_seconds` | Cuánto lleva esperando el trabajo más antiguo de la cola. |
| `tamandua_jobs_failed_24h` | Trabajos que fallaron en las últimas 24 horas. |
| `tamandua_workers_alive` / `tamandua_workers_docker` | Workers con latido reciente / que pueden lanzar los motores. |
| `tamandua_worker_last_heartbeat_age_seconds` | Segundos desde el último latido. |
| `tamandua_runs_24h{type,status}` | Ejecuciones creadas en las últimas 24 horas. |
| `tamandua_run_duration_seconds_24h{type,status,quantile}` | Duración de las que terminaron: p50, p95 y el máximo (`quantile="1"`). |
| `tamandua_info{version}` | Versión que sirve el endpoint. |

```yaml
# prometheus.yml
scrape_configs:
  - job_name: tamandua
    scheme: https
    metrics_path: /api/metrics
    authorization: { credentials_file: /etc/prometheus/tamandua-token }
    static_configs: [{ targets: ["tamandua.example.com"] }]
```

Recógelas a través del dominio (la API solo acepta su `Host` público). Alertas que merecen la pena:

```yaml
- alert: TamanduaNoWorker
  expr: tamandua_workers_alive == 0 or tamandua_workers_docker == 0
  for: 5m
- alert: TamanduaQueueStuck
  expr: tamandua_jobs_oldest_queued_age_seconds > 3600
- alert: TamanduaJobsFailing
  expr: tamandua_jobs_failed_24h > 5
```

**Logs.** `make logs` (API) y `make logs SERVICE=worker|caddy|backup`. Docker los rota (10 MB × 5 por servicio). El log de accesos de Caddy va en JSON y oculta las cookies y `Authorization`.

## Endurecimiento

- **El socket de Docker es root.** El worker lanza los motores a través de él, así que quien se haga con el worker controla el servidor. Tamandua mantiene el socket lejos del servicio que atiende peticiones (la API no lo tiene), pero la frontera de verdad es la máquina: una **VM dedicada**, sin otras aplicaciones, sin otros inquilinos y con solo los administradores en el grupo `docker`.
- **Segundo factor para todos** (`TAMANDUA_REQUIRE_TOTP=all`), y da de baja a quien se vaya.
- **Acota quién llega** si tu equipo tiene direcciones fijas: permite el 443 solo desde ellas en el cortafuegos del proveedor.
- **La dirección real del cliente.** Detrás de Caddy, la API se fía de `X-Forwarded-For` (`TAMANDUA_FORWARDED_ALLOW_IPS`, que pone el overlay) porque solo Caddy, el worker y PostgreSQL llegan a ella, y Caddy sustituye cualquier `X-Forwarded-For` que mande un cliente. Así, el límite de intentos de inicio de sesión y el log de auditoría ven la dirección de cada persona y no la del proxy.
- **Lo que añade el proxy.** Redirección de HTTP a HTTPS, HTTP/2 y HTTP/3, un límite de 2 MB por petición (el de la app es 1 MB), tiempos máximos para cabeceras y cuerpo, compresión solo para los ficheros estáticos del panel, y sin cabeceras `Server` ni `Via`. Las cabeceras de seguridad (CSP, HSTS, nosniff, frame, referrer) siguen siendo las de la app, así que hay un único juego coherente.
- **Imágenes.** Todo lo de terceros va fijado por digest; las imágenes publicadas están firmadas y llevan SBOM y procedencia SLSA (`docker buildx imagetools inspect ghcr.io/brayansstivens/tamandua:0.9 --format '{{json .SBOM}}'`).

## Coolify y Dokploy

Las dos plataformas ponen delante su propio proxy (Traefik) y sus certificados, así que Caddy sobra: despliega **solo `compose.yaml`** como aplicación Docker Compose desde el repositorio Git y deja que la plataforma lleve tu dominio al **servicio `api`, puerto 8766**. Estas notas siguen el comportamiento documentado de cada plataforma; todavía no hemos probado Tamandua en ellas.

Variables que hay que definir en la plataforma (las escribe en `.env`, que es lo que leen los servicios):

```bash
TAMANDUA_DB_PASSWORD=<openssl rand -hex 24>
TAMANDUA_PUBLIC_URL=https://tamandua.example.com
TAMANDUA_ALLOWED_ORIGINS=https://tamandua.example.com
TAMANDUA_FORWARDED_ALLOW_IPS=*              # solo el proxy de la plataforma llega a la api
TAMANDUA_METRICS_TOKEN=<openssl rand -hex 32>
TAMANDUA_UID=1000
TAMANDUA_GID=1000
DOCKER_SOCKET_GID=<stat -c %g /var/run/docker.sock, en el servidor>
```

A tener en cuenta en las dos:

- El worker monta `/var/run/docker.sock` y lanza contenedores hermanos que montan carpetas por su ruta **en el host**. El worker averigua esas rutas inspeccionándose a sí mismo, así que los montajes tienen que ser carpetas reales del host (no volúmenes con nombre).
- `config/` tiene que sobrevivir a los redespliegues: pon en `TAMANDUA_HOST_CONFIG_DIR` una ruta absoluta del servidor (por ejemplo `/srv/tamandua/config`, del usuario `TAMANDUA_UID`). Perderla obliga a volver a introducir todos los secretos. `data/` solo guarda cachés y logs.
- El servicio `opengrep` construye la imagen del motor y termina: es lo esperado, no un despliegue fallido.
- La plataforma construye las imágenes a partir del repositorio (allí no se usa `compose.images.yaml`). El primer despliegue tarda unos minutos.
- **Coolify:** recurso de tipo *Docker Compose*, ubicación del compose `/compose.yaml`. Coolify conserva los montajes `./data` en la carpeta de la aplicación entre despliegues.
- **Dokploy:** servicio de tipo *Compose*, ruta `./compose.yaml`. Cada despliegue vuelve a clonar el código, así que lleva `TAMANDUA_HOST_CONFIG_DIR` fuera del clon (Dokploy sugiere `../files/`).
- Los consejos de endurecimiento siguen valiendo: un PaaS que en el mismo servidor también ejecuta aplicaciones de otras personas es justo lo que el socket de Docker vuelve arriesgado.

Si algo falla, [solucion-problemas.md](solucion-problemas.md) recoge las causas habituales; para problemas del proxy, `make logs SERVICE=caddy`.
