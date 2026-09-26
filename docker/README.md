# docker/

Definiciones de imagen. Se construyen desde la raíz del repositorio con `make build` (o `docker compose build`); no hace falta entrar aquí.

| Carpeta | Imagen | Notas |
| --- | --- | --- |
| `app/` | `tamandua/app:<versión>` | Panel + API + cola de análisis. Multi-etapa: Node solo compila el panel. Bases fijadas por digest, usuario sin privilegios, etiquetas OCI. |
| `engines/opengrep/` | `tamandua/opengrep:1.30.0` | Motor SAST. Descarga el binario oficial y lo compara con su SHA-256; si no coincide, la construcción falla. `VERIFY.md` explica la verificación con Cosign. |

Trivy y Gitleaks no se construyen: se usan sus imágenes oficiales fijadas por digest (ver `tamandua/modules/scanning/engines.py`).

Para subir de versión un motor: cambia versión y digest (o SHA-256) en un solo sitio, `tamandua/modules/scanning/engines.py` y el Dockerfile correspondiente; `tests/test_packaging.py` comprueba que compose y el código coinciden.

Más detalles, endurecimiento y referencia de comandos en [docs/contenedores.md](../docs/contenedores.md).
