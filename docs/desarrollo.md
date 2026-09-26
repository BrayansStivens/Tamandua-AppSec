# Desarrollo

Para contribuir o ejecutar Tamandua sin contenedores. Lee también [CONTRIBUTING.md](../CONTRIBUTING.md).

## Sin contenedores

Requiere Python 3.12+ y Node 22. Sin Docker no corren los motores (Trivy, Gitleaks, Opengrep): el panel lo indica en cada análisis.

```bash
make dev-setup   # .venv con las dependencias de Python y node_modules del panel
make web         # compila el panel en tamandua/app/static/
make dev         # servidor en http://127.0.0.1:8767 con datos en .dev/ (no toca los de Docker)
make check       # pruebas y contratos de arquitectura del backend + tipos y lint del panel
```

`make dev` usa el puerto 8767 y la carpeta `.dev/` para que puedas tenerlo a la vez que la instancia de Docker. Para recarga en caliente del panel, `cd web && npm run dev` (Vite reenvía `/api` al backend).

La CLI usa el mismo almacén que el panel (en Docker: `make cli ARGS="…"`):

```bash
.venv/bin/python -m appsec_agent --data-dir .dev/data sources
.venv/bin/python -m appsec_agent --data-dir .dev/data scan-repository --source-id local:appsec-agent
.venv/bin/python -m appsec_agent --data-dir .dev/data runs
```

## Laboratorio sintético

`fixtures/tenant-api-lab` es una API de prueba con cinco fallos conocidos y sus variantes corregidas. Sirve para comprobar el motor de pruebas dinámicas durante el desarrollo; no aparece en el panel.

```bash
.venv/bin/python -m appsec_agent --data-dir .dev/data scan-fixture --variant both
```

## Paginación de la API

`GET /api/runs/page?limit&offset&status&type&q` pagina en el servidor sobre `data/runs/index.json`, un índice ligero de una fila por ejecución que se mantiene al guardar y se reconstruye si no cuadra con las carpetas; con mil ejecuciones no se leen mil archivos con sus hallazgos. El panel usa el mismo hook de paginación en la lista de análisis, el selector de ejecución y la tabla de hallazgos.

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

### Añadir o migrar una ruta de la API

Las rutas nuevas van en FastAPI, en `tamandua/app/api/<contexto>.py`: parámetros y respuesta con modelos Pydantic,
seguridad con `guard(Policy(public=…, admin=…, action=…))` (la misma tubería que el router clásico: CSRF, sesión,
segundo factor, rol) y la lógica en el módulo de negocio, nunca en la ruta. Lo que aún no se ha migrado lo atiende el
router clásico detrás de FastAPI (`app/api/legacy.py`); al migrar una ruta se borra de `app/http/routes_*.py`.

Después, `make openapi` regenera el esquema y los tipos TypeScript del panel (`web/src/shared/api/`), que se usan con
`apiGet('/api/…')`: si la API y el panel no cuadran, falla `tsc`. El CI comprueba que el esquema está al día.

### Cambiar el formato de algo que ya está en `data/`

Quien actualiza Tamandua ya tiene datos: una versión nueva nunca debe romperlos ni pedirle que haga nada a mano.

1. **Lector tolerante.** El código lee también el formato anterior: `dict.get` con valor por defecto para
   campos nuevos, sin suponer tipos que antes no existían. Leer nunca lanza por un campo que falta.
2. **Migración si hay que reescribir.** Se añade al final de `MIGRATIONS` en `tamandua/app/data_migrations.py`:
   idempotente (repetirla no daña), con las rutas que toca en `touches` (se copian antes) y rápida en
   instalaciones grandes. Nunca se reordena ni se borra una migración publicada: la versión es su posición.
3. **Prueba con datos viejos** en `tests/test_migrations.py` (o junto al módulo): se escriben a mano en el
   formato anterior, se migra y se comprueba el resultado.

Si el cambio solo añade un campo que puede faltar, basta con el punto 1: no hace falta migración.

`npm run build` actualiza los activos servidos por Python. Para recarga en desarrollo usa `npm run dev`; Vite reenvía `/api` al backend en 8766.
