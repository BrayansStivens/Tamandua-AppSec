# Contribuir

Gracias por el interés. Antes de abrir un PR:

1. Abre un issue para hablar de cambios grandes.
2. Corre las pruebas y el lint:

   ```bash
   make dev-setup   # una vez
   make check       # pruebas del backend + tipos y lint del panel
   ```

   El CI ([`ci.yml`](.github/workflows/ci.yml)) repite esto en cada PR, comprueba que `appsec_agent/static` está
   recompilado (`make web`) y analiza el PR con el propio Tamandua: bloquea si introduce algo de severidad alta o superior.

3. Mantén las reglas de la casa:
   - **Sin dependencias nuevas en el backend** salvo que sea imprescindible: hoy solo usa la biblioteca estándar y `cryptography`.
   - **Ningún secreto en logs, respuestas ni ficheros de `data/`.** Los secretos van por `vault.py`.
   - Cada ruta nueva se declara con su permiso, su cabecera de acción (POST) y su tamaño máximo de cuerpo; la prueba de la tabla de rutas lo comprueba.
   - Lo que no se pudo probar se dice (`not_tested` con motivo); nunca se presenta como «sin vulnerabilidades».
   - Textos de la interfaz y de la documentación en español.
   - Si cambias el formato de algo que ya está en `data/`: lector tolerante y, si hay que reescribir datos, una migración con su prueba (ver [desarrollo.md](docs/desarrollo.md)).
4. Nunca pegues tokens, claves ni logs sin revisar en issues o PRs.

**Firma del CLA.** En tu primer PR, un bot te pedirá aceptar el [Acuerdo de Licencia de Contribución](CLA.md) con un comentario. Conservas los derechos de autor; el acuerdo permite distribuir tu aporte bajo la [AGPL-3.0](LICENSE) (las reglas de `rules/`, bajo MIT) y también en una posible edición comercial, con el compromiso de que siga disponible en la edición libre.

Detalles para ejecutar sin contenedores en [docs/desarrollo.md](docs/desarrollo.md).
