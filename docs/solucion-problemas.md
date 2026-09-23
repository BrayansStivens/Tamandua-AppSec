# Solución de problemas

Lo primero, siempre:

```bash
docker compose ps
docker compose logs --tail 100 appsec
```

Los logs de la app no contienen contraseñas, tokens ni claves: puedes compartirlos al pedir ayuda. Aun así, revísalos antes por si incluyen nombres de repositorios o dominios que prefieras no publicar.

| Síntoma | Causa probable | Solución |
| --- | --- | --- |
| `opengrep` aparece como *Exited* | Es su comportamiento: solo construye la imagen del motor y comprueba que arranca. | Nada. |
| La construcción falla en `sha256sum -c` | El binario de Opengrep descargado no coincide con el hash fijado. | No continúes: reintenta más tarde y, si persiste, abre un issue. Nunca quites la comprobación. |
| El panel no abre en `127.0.0.1:8766` | Otro servicio usa el puerto o el contenedor no arrancó. | Cambia `APPSEC_PORT` y también `APPSEC_AGENT_PUBLIC_URL` y `APPSEC_AGENT_ALLOWED_ORIGINS` en `.env`. |
| *Host no permitido* (403) | Abres el panel con una URL que no está en `APPSEC_AGENT_ALLOWED_ORIGINS`. | Añádela en `.env` y reinicia. |
| El contenedor se para con *expone el panel por HTTP en claro* | `APPSEC_AGENT_PUBLIC_URL` apunta fuera de esta máquina sin HTTPS. | Pon HTTPS delante (ver README) o vuelve a `http://127.0.0.1:8766`. |
| No encuentro el código de configuración | Salió en los logs del primer arranque. | `docker compose logs appsec \| grep -A1 "Primer arranque"`. Si ya hay un usuario creado, el código no existe: entra con ese usuario. |
| `Permission denied` en `data/` o `config/` | Las carpetas las creó Docker como root. | `sudo chown -R $(id -u):$(id -g) data config` y pon tu UID/GID en `.env`. |
| *No se pudo descifrar un secreto* | Cambió `APPSEC_AGENT_MASTER_KEY` o se perdió `config/master.key`. | Restaura la clave; si no es posible, *Olvidar la App* y vuelve a conectar GitHub, IA y Jira. |
| Un motor sale como *No probado* | Docker no es accesible desde el contenedor o falta la imagen. | Comprueba que `/var/run/docker.sock` está montado y que `docker compose up --build` terminó sin errores. |
| El CVE tracker va lento al empezar | La copia local de NVD se está descargando (se ve el progreso arriba). | Espera, o añade `APPSEC_AGENT_NVD_API_KEY`. |
| Un análisis quedó *Fallido* tras reiniciar | Al arrancar se marcan como fallidos los que estaban a medias. | Vuelve a lanzarlo. |
| Perdí el segundo factor | — | Otro administrador lo quita en **Usuarios**, o por CLI: `docker compose exec appsec python -m appsec_agent --data-dir /data user reset-totp --username tu-usuario`. |
| Olvidé la contraseña | — | **Usuarios → Enlace de contraseña**, o `user reset-password` por CLI. |
