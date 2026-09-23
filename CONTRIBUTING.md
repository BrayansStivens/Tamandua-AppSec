# Contribuir

Gracias por el interés. Antes de abrir un PR:

1. Abre un issue para hablar de cambios grandes.
2. Corre las pruebas y el lint:

   ```bash
   .venv/bin/python -m unittest discover -s tests
   (cd web && npm run lint && npm run build)
   ```

3. Mantén las reglas de la casa:
   - **Sin dependencias nuevas en el backend** salvo que sea imprescindible: hoy solo usa la biblioteca estándar y `cryptography`.
   - **Ningún secreto en logs, respuestas ni ficheros de `data/`.** Los secretos van por `vault.py`.
   - Cada ruta nueva se declara con su permiso, su cabecera de acción (POST) y su tamaño máximo de cuerpo; la prueba de la tabla de rutas lo comprueba.
   - Lo que no se pudo probar se dice (`not_tested` con motivo); nunca se presenta como «sin vulnerabilidades».
   - Textos de la interfaz y de la documentación en español.
4. Nunca pegues tokens, claves ni logs sin revisar en issues o PRs.

Al enviar un PR aceptas que tu contribución se publique bajo la misma licencia del proyecto, [AGPL-3.0](LICENSE) (las reglas de `rules/`, bajo MIT).

Detalles para ejecutar sin contenedores en [docs/desarrollo.md](docs/desarrollo.md).
