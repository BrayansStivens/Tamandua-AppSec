# Seguridad

AppSec Agent lee el código de tus repositorios y guarda credenciales de GitHub, IA y Jira. Este documento explica cómo protege esa información, qué sale de tu máquina y qué concesiones hace. Para reportar una vulnerabilidad, ve a [SECURITY.md](../SECURITY.md).

## Secretos

| Secreto | Dónde vive | Quién lo ve |
| --- | --- | --- |
| Clave privada de la GitHub App | `config/secrets.vault`, cifrada | Solo el proceso del servidor. A GitHub va un JWT firmado, nunca la clave. |
| Claves de OpenAI / Anthropic | `config/secrets.vault`, cifradas | Solo el servidor; se validan contra el proveedor antes de guardarse. El panel muestra los 4 últimos caracteres. |
| Token de Jira | `config/secrets.vault`, cifrado | Igual que las anteriores. |
| Tokens de registros de contenedores | `config/secrets.vault`, cifrados | Solo el servidor. Llegan a Trivy y Grype por variable de entorno (`-e NOMBRE` sin valor en la orden), nunca en la línea de comandos. |
| Tokens de instalación de GitHub | Memoria, 1 h | Se renuevan solos; nunca se escriben en disco. |
| Clave maestra | `config/master.key` (0400) o `APPSEC_AGENT_MASTER_KEY` | Quien administra el servidor. |
| Contraseñas de usuarios | `data/auth/users.json`, solo hash scrypt | Nadie: no son recuperables. |
| Cookies de sesión | `data/auth/sessions.json`, solo su hash | Copiar el fichero no da acceso. |

**Cifrado.** AES-256-GCM, un nonce aleatorio por secreto y el nombre del secreto como dato asociado: un valor cifrado no se puede mover a otra entrada sin que falle el descifrado, y cualquier manipulación se detecta. Si la clave maestra no descifra, el servidor lo dice en lugar de usar datos corruptos.

**Separación.** `config/` (secretos) y `data/` (todo lo demás) son carpetas distintas. `data/` es lo que se suele copiar, enviar para depurar o subir con los logs: no lleva ningún secreto. Para separar también la clave del almacén, define `APPSEC_AGENT_MASTER_KEY` desde tu gestor de secretos en vez de dejar `master.key` junto a `secrets.vault`.

**Logs.** No se registran cuerpos de petición, cabeceras, contraseñas, códigos TOTP ni cookies. Además, todo mensaje pasa por un filtro que tacha:

- patrones conocidos: `ghp_`, `ghs_`, `github_pat_`, `sk-…`, `xox…`, `AKIA…`, `ATATT…`, JWT, `Bearer …`, `Basic …` y bloques `-----BEGIN … PRIVATE KEY-----`;
- literalmente, cualquier valor guardado en el almacén, aunque no siga ningún patrón.

**Navegador.** Ningún secreto vuelve al navegador. La clave `.pem` se lee en tu navegador y viaja una sola vez al servidor al conectarla; el panel no la conserva.

## Acceso al panel

- **Primer administrador** con un código de un solo uso que solo aparece en la consola del servidor: quien abra la URL antes que tú no puede quedarse con la instancia.
- **Contraseñas** con scrypt (N=2¹⁵, r=8, p=1), mínimo 12 caracteres. Un usuario inexistente cuesta lo mismo que uno real, así que el tiempo de respuesta no delata cuáles existen.
- **Segundo factor** TOTP (RFC 6238) obligatorio para administradores por defecto, con 8 códigos de respaldo de un solo uso. Un código ya usado no vale dos veces.
- **Sesiones** del lado del servidor, con cookie `HttpOnly`, `SameSite=Strict` y `Secure` con HTTPS. Cambiar la contraseña, activar TOTP o que un administrador restablezca credenciales cierra las demás sesiones.
- **Límite de intentos** por usuario y por dirección: tras 5 fallos, bloqueo progresivo de 30 s a 15 min. También en el alta inicial y en la vuelta de GitHub.
- **CSRF**: cada POST exige un `Origin` permitido y una cabecera de acción propia de su ruta.
- **Roles**: `admin` conecta integraciones, gestiona usuarios y acepta riesgos; `member` analiza y triagea.

## Transporte

- El puerto se publica solo en `127.0.0.1` por defecto.
- Si `APPSEC_AGENT_PUBLIC_URL` apunta fuera de esta máquina y no es HTTPS, **el servidor no arranca**. Solo `APPSEC_AGENT_ALLOW_INSECURE_HTTP=1` lo permite, bajo tu responsabilidad.
- Con HTTPS: HSTS (1 año) y cookies `Secure`. TLS 1.2 como mínimo si el propio servidor sirve TLS.
- Todas las respuestas llevan `Content-Security-Policy` estricta (sin scripts ni estilos en línea), `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` y `Permissions-Policy`.
- Las llamadas salientes van por HTTPS con verificación de certificado y **no siguen redirecciones**, para que una credencial nunca acabe en un destino distinto del previsto.

## Qué sale de tu máquina

| Destino | Qué se envía | Cuándo |
| --- | --- | --- |
| `api.github.com` | JWT de tu App, peticiones de repositorios y PRs; comentarios y estados de commit en tus PRs | Al conectar, analizar y revisar PRs. El código se **descarga** de GitHub; no se sube a ningún otro sitio. |
| `services.nvd.nist.gov` | Rangos de índices y de fechas | Copia local de CVE, en segundo plano. |
| `www.cisa.gov`, `epss.empiricalsecurity.com` | Nada: descarga de feeds públicos completos | Una vez al día. Se descargan enteros para no revelar qué CVE te interesan. |
| Registro de imágenes y base de Trivy | Nada propio | Al construir y cuando Trivy actualiza su base. |
| Registros de contenedores (Docker Hub, GHCR, ECR…) | Petición de la imagen que pides analizar, con tu token si lo guardaste | Al analizar una imagen. Los registros con IP privada se bloquean salvo `APPSEC_AGENT_ALLOW_PRIVATE_REGISTRIES=1`, para que el formulario no sirva de puente a tu red interna (SSRF). |
| `api.osv.dev` | Nombres y versiones de tus dependencias | **Solo si lo autorizas** en cada análisis. Por defecto no se usa. |
| Tu sitio de Jira | Título, descripción y prioridad de las incidencias que exportas | Solo si conectas Jira y pulsas exportar. |
| `api.openai.com`, `api.anthropic.com` | Tu clave, para comprobar que es válida | Solo al guardarla o probarla. Hoy la IA no recibe código ni hallazgos. |
| Tus dominios | Un `HEAD` HTTPS y una consulta DNS TXT | Solo cuando esté disponible el pentest web (en desarrollo). Solo a direcciones públicas. |

No hay telemetría.

## Análisis del código

- El código de los repositorios **nunca se ejecuta**: se analiza una instantánea en solo lectura.
- Los motores corren en contenedores efímeros con `--cap-drop ALL`, `no-new-privileges` y límites de memoria, CPU y procesos. Gitleaks y Opengrep no tienen red; Trivy y Grype solo la usan para su base de vulnerabilidades y, al analizar una imagen, para leerla del registro.
- Las imágenes de contenedor que analizas **no se ejecutan ni se construyen**: los motores leen el manifiesto y las capas.
- Las imágenes de Trivy, Gitleaks y Grype van fijadas por digest. La de Opengrep se construye con el binario oficial comprobado contra su SHA-256.
- Los valores de los secretos encontrados en tu código se redactan: en los hallazgos queda la ubicación y el tipo, no el valor.

## Concesiones conocidas

- **Socket de Docker.** La app lanza los motores a través de `/var/run/docker.sock`, lo que equivale a root en el host. Es el precio de no instalar nada más que Docker. Si abres el panel a más gente, ponlo detrás de un socket-proxy con lista blanca o separa el runner. Está en el plan de trabajo.
- **Clave maestra junto al almacén** si no defines `APPSEC_AGENT_MASTER_KEY`. Protege frente a una copia suelta de `secrets.vault`, no frente a alguien con acceso completo a `config/`.
- **Un solo workspace** por instalación: todos los usuarios ven todos los repositorios conectados.
- **Token de registro visible para root.** Mientras dura el análisis de una imagen privada, el token está en la configuración del contenedor del motor: lo puede leer quien tenga acceso a Docker en el host (que ya es root). Usa tokens de solo lectura.

## Recomendaciones

1. Mantén el panel en `127.0.0.1` salvo que necesites acceso remoto, y entonces usa HTTPS.
2. Activa TOTP para todos (`APPSEC_AGENT_REQUIRE_TOTP=all`) si varias personas lo usan.
3. Instala la App solo en los repositorios que quieras analizar (**Only select repositories**).
4. Guarda `config/` aparte de `data/` en tus copias.
5. Si una clave de la App se filtra: revócala en GitHub (*Private keys → Delete*), genera otra y vuelve a conectarla en **Integraciones**.
