# Instalación

## Requisitos

| | Mínimo | Notas |
| --- | --- | --- |
| Sistema | Linux, macOS o Windows con WSL2 | amd64 o arm64 (Apple Silicon incluido). |
| Docker | Engine 24+ y Compose v2.24+ | Docker Desktop, OrbStack o Docker Engine. `docker compose version` para comprobarlo. |
| Memoria | 4 GB libres | La app usa ~200 MB en reposo; cada análisis lanza un motor a la vez, limitado a 3 GB. |
| Disco | 5 GB libres | Imágenes (~0,9 GB), caché de vulnerabilidades de Trivy (~1,3 GB), copia local de NVD (~0,7 GB) y tus ejecuciones. |
| Red de salida | HTTPS a GitHub, NVD, CISA y EPSS | Detalle en [seguridad.md](seguridad.md#qué-sale-de-tu-máquina). No hace falta ninguna entrada desde internet. |
| Cuenta | GitHub (personal u organización que administres) | Para crear tu GitHub App. |

No hace falta instalar Python, Node ni los motores de análisis: todo va en contenedores.

## Primera instalación

```bash
git clone https://github.com/BrayansStivens/appsec-agent.git
cd appsec-agent
cp .env.example .env
mkdir -p data config
```

Edita `.env` y pon tu usuario del host en `APPSEC_UID` y `APPSEC_GID` (salen de `id -u` e `id -g`). Así los ficheros de `data/` y `config/` son tuyos y no de root. Después:

```bash
docker compose up --build -d
docker compose logs appsec
```

La primera construcción tarda unos minutos: compila el panel, descarga el binario de Opengrep y comprueba su SHA-256. Verás dos contenedores: `appsec-agent`, que se queda en marcha, y `opengrep`, que solo construye la imagen del motor y **termina enseguida**: es normal.

En los logs aparece un recuadro con el **código de configuración**:

```
================================================================
  Primer arranque: crea el administrador en el panel con este código
      ABCD-EFGH-JKLM
  (solo sirve una vez y solo mientras no haya usuarios)
================================================================
```

Abre <http://127.0.0.1:8766>, escribe ese código y crea tu usuario administrador. El código demuestra que eres quien controla el servidor: sin él, el primero que abriera la URL podría quedarse con la instancia. Si reinicias antes de usarlo, sale uno nuevo.

Luego:

1. **Cuenta → Segundo factor**: activa TOTP con tu app de autenticación y guarda los códigos de respaldo. Es obligatorio para administradores.
2. **Integraciones**: crea y conecta tu GitHub App con la guía del panel (también en [github-app.md](github-app.md)).
3. **Repositorios**: elige uno y pulsa **Analizar**.

La copia local de NVD para el CVE tracker se descarga sola en segundo plano: unas horas sin API key, mucho menos con `APPSEC_AGENT_NVD_API_KEY` (gratuita en <https://nvd.nist.gov/developers/request-an-api-key>). Todo lo demás funciona mientras tanto.

## Actualizar

```bash
git pull
docker compose up --build -d
```

`data/` y `config/` se conservan. Antes de actualizar conviene hacer una copia (ver abajo) y comprobar que no hay análisis en marcha en **Pentests**: un reinicio marca como fallidos los que estuvieran corriendo.

## Copias de seguridad

| Carpeta | Qué contiene | Cómo tratarla |
| --- | --- | --- |
| `data/` | Ejecuciones, hallazgos, usuarios (contraseñas con scrypt), logs, copia de NVD y cachés | Sin secretos en claro. Se puede excluir `data/feeds/` y `data/trivy-cache/`: se vuelven a descargar. |
| `config/` | `secrets.vault` (cifrado) y `master.key` | **Es la llave de tus credenciales.** Guárdala aparte de `data/` y con el mismo cuidado que una contraseña. |

```bash
docker compose stop appsec
tar czf appsec-data-$(date +%F).tgz --exclude=data/feeds --exclude=data/trivy-cache data
tar czf appsec-config-$(date +%F).tgz config        # guárdalo en otro sitio, cifrado
docker compose start appsec
```

Si pierdes `config/master.key` (o cambias `APPSEC_AGENT_MASTER_KEY`), los secretos guardados no se pueden descifrar: tendrás que volver a conectar la GitHub App y las claves de IA y Jira. El resto de datos no se pierde.

## Exponerlo en tu red o en internet

Por defecto el puerto solo se publica en `127.0.0.1`. Para abrirlo desde otras máquinas necesitas HTTPS: el servidor **se niega a arrancar** si `APPSEC_AGENT_PUBLIC_URL` no es loopback y no empieza por `https://`. La forma más sencilla es Caddy delante; está explicado en el [README](../README.md#usarlo-desde-otra-máquina-https).

Aunque uses HTTPS, ten en cuenta que la app controla Docker a través de su socket, lo que equivale a root en el host. Expón el panel solo a personas de confianza.

## Desinstalar

```bash
docker compose down
docker image rm appsec-agent/app:0.9 appsec-agent/opengrep:1.30.0
rm -rf data config        # borra tus datos y secretos: hazlo solo si ya no los necesitas
```

Borra también tu GitHub App en GitHub (*Settings → Developer settings → GitHub Apps → tu App → Advanced → Delete*), o al menos revoca su clave privada.
