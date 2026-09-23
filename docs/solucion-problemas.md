# Solución de problemas

Lo primero, siempre:

```bash
make doctor     # requisitos, permisos, puerto y motores
make status     # contenedores e imágenes de los motores
make logs
```

Los logs de la app no contienen contraseñas, tokens ni claves: puedes compartirlos al pedir ayuda. Aun así, revísalos antes por si incluyen nombres de repositorios o dominios que prefieras no publicar.

| Síntoma | Causa probable | Solución |
| --- | --- | --- |
| `opengrep` aparece como *Exited* | Es su comportamiento: solo construye la imagen del motor y comprueba que arranca. | Nada. |
| La construcción falla en `sha256sum -c` | El binario de Opengrep descargado no coincide con el hash fijado. | No continúes: reintenta más tarde y, si persiste, abre un issue. Nunca quites la comprobación. |
| El panel no abre en `127.0.0.1:8766` | Otro servicio usa el puerto o el contenedor no arrancó. | Cambia `APPSEC_PORT` y también `APPSEC_AGENT_PUBLIC_URL` y `APPSEC_AGENT_ALLOWED_ORIGINS` en `.env`. |
| *Host no permitido* (403) | Abres el panel con una URL que no está en `APPSEC_AGENT_ALLOWED_ORIGINS`. | Añádela en `.env` y reinicia. |
| El contenedor se para con *expone el panel por HTTP en claro* | `APPSEC_AGENT_PUBLIC_URL` apunta fuera de esta máquina sin HTTPS. | Pon HTTPS delante (ver README) o vuelve a `http://127.0.0.1:8766`. |
| No encuentro el código de configuración | Salió en los logs del primer arranque. | `make setup-code`. Si ya hay un usuario creado, el código no existe: entra con ese usuario. |
| `Permission denied` en `data/` o `config/` | Las carpetas las creó Docker como root. | `sudo chown -R $(id -u):$(id -g) data config`; si tu `.env` tiene otro UID/GID, bórralo y ejecuta `make setup`. |
| *No se pudo descifrar un secreto* | Cambió `APPSEC_AGENT_MASTER_KEY` o se perdió `config/master.key`. | Restaura la clave; si no es posible, *Olvidar la App* y vuelve a conectar GitHub, IA y Jira. |
| Un motor sale como *No probado* | Docker no es accesible desde el contenedor o falta la imagen. | `make status` dice qué imagen falta: `make build` para Opengrep y `make engines` para Trivy y Gitleaks. |
| El CVE tracker va lento al empezar | La copia local de NVD se está descargando (se ve el progreso arriba). | Espera, o añade `APPSEC_AGENT_NVD_API_KEY`. |
| Linux: análisis sin hallazgos que no cuadran, o cachés `trivy-cache-<uid>` nuevas | Antes del 23-sep-2026 se lanzaban los motores como root sin capacidades, que en Linux no puede leer las carpetas privadas de la app y devolvía cero hallazgos sin avisar. Ahora corren con el UID de la app; si una caché antigua la creó root, se usa una nueva a su lado. | Vuelve a lanzar los análisis hechos en Linux antes de actualizar. Las cachés viejas (`data/trivy-cache`, `data/grype-cache`) se pueden borrar con `sudo rm -rf` si ya existe la versión con sufijo. |
| Un análisis quedó *Fallido* tras reiniciar | Al arrancar se marcan como fallidos los que estaban a medias. | Vuelve a lanzarlo. |
| Perdí el segundo factor | — | Otro administrador lo quita en **Usuarios**, o por CLI: `make cli ARGS="user reset-totp --username tu-usuario"`. |
| Olvidé la contraseña | — | **Usuarios → Enlace de contraseña**, o `user reset-password` por CLI. |
