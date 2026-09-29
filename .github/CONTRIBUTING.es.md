[English](CONTRIBUTING.md) · Español

# Contribuir

Gracias por el interés. Antes de abrir un PR:

1. Abre un issue para hablar de cambios grandes.
2. Corre las pruebas y el lint:

   ```bash
   make dev-setup   # una vez
   make check       # pruebas y contratos de arquitectura del backend + tipos y lint del panel
   ```

   El CI ([`ci.yml`](.github/workflows/ci.yml)) repite esto en cada PR, comprueba que `tamandua/app/static` está
   recompilado (`make web`) y analiza el PR con el propio Tamandua: bloquea si introduce algo de severidad alta o superior.

3. Mantén las reglas de la casa:
   - **Sin dependencias nuevas en el backend** salvo que sea imprescindible: hoy son las de `requirements.txt` (FastAPI, uvicorn, Pydantic, SQLAlchemy, Alembic, psycopg, `cryptography` y ReportLab), con versión fijada.
   - **Ningún secreto en logs, respuestas ni ficheros de `data/`.** Los secretos van por `vault.py`.
   - Cada ruta nueva se declara con su permiso, su cabecera de acción (POST) y su tamaño máximo de cuerpo; la prueba de la tabla de rutas lo comprueba.
   - Lo que no se pudo probar se dice (`not_tested` con motivo); nunca se presenta como «sin vulnerabilidades».
   - Código, identificadores y comentarios en inglés. Todo texto que lee una persona (interfaz, errores, hallazgos, informes) va en inglés y en español por los catálogos: interpreta, no traduzcas ([`.claude/skills/tamandua-i18n/SKILL.md`](.claude/skills/tamandua-i18n/SKILL.md)). La documentación, en `docs/` (inglés) y `docs/es/` (español).
   - Si cambias el formato de algo que ya está en `data/`: lector tolerante y, si hay que reescribir datos, una migración con su prueba (ver [desarrollo.md](docs/es/desarrollo.md)).
4. Nunca pegues tokens, claves ni logs sin revisar en issues o PRs.

**Firma del CLA.** En tu primer PR, un bot te pedirá aceptar el [Acuerdo de Licencia de Contribución](CLA.es.md) con un comentario. Conservas los derechos de autor; el acuerdo permite distribuir tu aporte bajo la [AGPL-3.0](LICENSE) (las reglas de `rules/`, bajo MIT) y también en una posible edición comercial, con el compromiso de que siga disponible en la edición libre.

Detalles para ejecutar sin contenedores en [docs/es/desarrollo.md](docs/es/desarrollo.md).
