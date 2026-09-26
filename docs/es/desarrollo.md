[English](../development.md) · Español

# Desarrollo

Para contribuir o ejecutar Tamandua sin contenedores. Lee también [CONTRIBUTING.es.md](../../CONTRIBUTING.es.md).

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
.venv/bin/python -m tamandua --data-dir .dev/data sources
.venv/bin/python -m tamandua --data-dir .dev/data scan-repository --source-id github:org/repo
.venv/bin/python -m tamandua --data-dir .dev/data runs
```

## Paginación de la API

`GET /api/runs/page?limit&offset&status&type&q` filtra, cuenta y pagina en PostgreSQL sobre la fila ligera de cada ejecución (columna `row` de `runs`); con mil ejecuciones no se cargan mil registros con sus hallazgos. El panel usa el mismo hook de paginación en la lista de análisis, el selector de ejecución y la tabla de hallazgos.

## Logs

`data/logs/app.log` recibe una línea JSON por evento (hora, nivel, componente, identificador de ejecución, método, ruta, estado, duración), rotada a 10 MB × 5; en consola sale legible. `TAMANDUA_LOG_LEVEL=DEBUG` para depurar. No se registran cuerpos, cabeceras ni tokens, y `redact()` tacha patrones de credenciales que pudieran colarse en un mensaje.

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

Las pruebas necesitan PostgreSQL: `make test` arranca uno efímero en Docker (datos en memoria) y da a cada prueba su propio esquema (`TAMANDUA_DB_ISOLATE=data-dir`). Para correr una sola: `TAMANDUA_DATABASE_URL=$(sh scripts/test-db.sh) TAMANDUA_DB_ISOLATE=data-dir .venv/bin/python -m unittest discover -s tests -p 'test_x.py'`.

### Añadir o migrar una ruta de la API

Las rutas nuevas van en FastAPI, en `tamandua/app/api/<contexto>.py`: parámetros y respuesta con modelos Pydantic,
seguridad con `guard(Policy(public=…, admin=…, action=…))` (CSRF, sesión, segundo factor, rol; ver
`app/api/security.py`) y la lógica en el módulo de negocio, nunca en la ruta. Las rutas anteriores siguen declaradas
en tabla con `@route` en `app/api/routes/<área>.py` (misma tubería, registradas por `routing.mount`); al tocar una a
fondo, conviene pasarla a tipada.

Después, `make openapi` regenera el esquema y los tipos TypeScript del panel (`web/src/shared/api/`), que se usan con
`apiGet('/api/…')`: si la API y el panel no cuadran, falla `tsc`. El CI comprueba que el esquema está al día.

### Cambiar el esquema de la base de datos

Las tablas se definen en `tamandua/modules/<contexto>/tables.py`. Un cambio lleva su migración de Alembic:

```bash
TAMANDUA_DATABASE_URL=… .venv/bin/python -c "from alembic import command; from tamandua.app.database import config; command.revision(config(), message='qué cambia', autogenerate=True)"
```

Revisa el archivo generado en `tamandua/app/alembic/versions/`. `tests/test_database.py` falla si las tablas del código y
las migraciones no coinciden.

### Cambiar el formato de datos que ya existen

Quien actualiza Tamandua ya tiene datos: una versión nueva nunca debe romperlos ni pedirle que haga nada a mano.

1. **Lector tolerante.** El código lee también el formato anterior (en un documento JSONB o una columna `record`):
   `dict.get` con valor por defecto para campos nuevos, sin suponer tipos que antes no existían.
2. **Migración si hay que reescribir.** Un cambio de tablas va en Alembic (arriba). Reescribir contenido va al final
   de `MIGRATIONS` en `tamandua/app/data_migrations.py`: idempotente, rápida en instalaciones grandes y sin
   reordenar ni borrar nunca una publicada (la versión es su posición).
3. **Prueba con datos viejos** en `tests/test_migrations.py` (o junto al módulo).

Si el cambio solo añade un campo que puede faltar, basta con el punto 1: no hace falta migración.

`npm run build` actualiza los activos servidos por Python. Para recarga en desarrollo usa `npm run dev`; Vite reenvía `/api` al backend en 8766.

## Textos e idiomas

Tamandua habla inglés y español. **El código, los identificadores y los comentarios van en inglés**; todo lo que lee
una persona (panel, errores de la API, hallazgos, guías de corrección, progreso, informes, comentarios de PR, avisos)
existe en los dos idiomas. Antes de añadir o cambiar cualquiera de esos textos, lee
[`.claude/skills/tamandua-i18n/SKILL.md`](../../.claude/skills/tamandua-i18n/SKILL.md):

- **Catálogos, no literales.** Panel: `web/src/shared/i18n/locales/{en,es}/<namespace>.json` con `t('…')`. Servidor:
  `tamandua/shared/i18n/locales/{en,es}/<namespace>.json`.
- **Se guardan códigos, no frases.** En el servidor, `msg("namespace.key", **params)` crea un mensaje sin idioma que
  se muestra al leerlo, en el idioma de quien lo lee (`localize`, `text`); `t()` solo para lo que no se guarda.
- **Interpretar, no traducir.** El inglés es el origen y el respaldo; el español dice lo mismo como lo diría un
  ingeniero de seguridad hispanohablante, nunca palabra por palabra. La skill tiene la voz y el glosario.
- **Pruebas.** `tests/test_i18n.py` (parte de `make test`) comprueba que en/es tienen las mismas claves y los mismos
  `{{params}}`, y que toda clave literal usada en el código existe. Las pruebas corren con
  `TAMANDUA_DEFAULT_LOCALE=es`; el inglés se comprueba de forma explícita con `Accept-Language: en`.

La documentación sigue la misma regla: inglés en `docs/`, español en `docs/es/`, y cada página enlaza con la otra.
