# Desarrollo

Para contribuir o ejecutar AppSec Agent sin contenedores. Lee también [CONTRIBUTING.md](../CONTRIBUTING.md).

## Sin contenedores

Requiere Python 3.12+ y Node 22 para compilar el panel. Sin Docker no corren los motores (Trivy, Gitleaks, Opengrep): el panel lo indica en cada análisis.

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
(cd web && npm ci && npm run build)
.venv/bin/python -m appsec_agent serve
```

La CLI usa el mismo almacén local que el panel cuando se ejecuta desde esta carpeta:

```bash
python3 -m appsec_agent sources
python3 -m appsec_agent scan-repository --source-id local:appsec-agent
python3 -m appsec_agent runs
```

## Paginación de la API

`GET /api/runs/page?limit&offset&status&type&q` pagina en el servidor sobre `data/runs/index.json`, un índice ligero de una fila por ejecución que se mantiene al guardar y se reconstruye si no cuadra con las carpetas; con mil ejecuciones no se leen mil archivos con sus hallazgos. El panel usa el mismo hook de paginación en la lista de pentests, el selector de ejecución y la tabla de hallazgos.

## Logs

`data/logs/app.log` recibe una línea JSON por evento (hora, nivel, componente, identificador de ejecución, método, ruta, estado, duración), rotada a 10 MB × 5; en consola sale legible. `APPSEC_AGENT_LOG_LEVEL=DEBUG` para depurar. No se registran cuerpos, cabeceras ni tokens, y `redact()` tacha patrones de credenciales que pudieran colarse en un mensaje.

## Desarrollo y pruebas

El frontend React/TypeScript usa [shadcn/ui](https://ui.shadcn.com/docs/installation/vite), Tailwind y Lucide. El selector de tema es un componente shadcn; soporta sistema, claro y oscuro (oscuro por defecto).

```bash
cd web
npm ci
npm run build
npm run lint
cd ..
.venv/bin/python -m unittest discover -s tests -v
```

Las pruebas necesitan `cryptography` (almacén cifrado y firma del JWT): córrelas con el venv, `.venv/bin/python -m unittest discover -s tests`.

`npm run build` actualiza los activos servidos por Python. Para recarga en desarrollo usa `npm run dev`; Vite reenvía `/api` al backend en 8766.
