# Conectar GitHub

Cada instalación de Tamandua usa **su propia** GitHub App: la creas tú, en tu cuenta o en una organización que administres, y solo se puede instalar ahí. GitHub no permite crear Apps por API, así que se hace en su formulario. El panel (**Integraciones**) muestra esta misma guía con los valores ya rellenos para tu instalación y botones para copiarlos.

## 1. Crear la App

Abre el formulario de nueva App:

- Cuenta personal: <https://github.com/settings/apps/new>
- Organización: `https://github.com/organizations/<tu-org>/settings/apps/new`

Rellena solo esto:

| Campo | Valor |
| --- | --- |
| **GitHub App name** | El que quieras, p. ej. `Tamandua`. Tiene que ser único en todo GitHub: si ya existe, añade tu equipo. |
| **Homepage URL** | Cualquier URL tuya; p. ej. tu perfil de GitHub o la URL de tu panel. |
| **Callback URL** | Vacío. |
| **Request user authorization (OAuth) during installation** | Sin marcar. |
| **Setup URL** (opcional) | `http://127.0.0.1:8766/oauth/callback` (o tu URL pública + `/oauth/callback`) y marca **Redirect on update**. Así vuelves al panel al instalar. |
| **Webhook → Active** | Desmarcado. El panel consulta los PRs por su cuenta. |

**Repository permissions**, solo estos cuatro:

| Permiso | Nivel | Para qué |
| --- | --- | --- |
| Contents | Read-only | Descargar el código para analizarlo. |
| Metadata | Read-only | Obligatorio en toda App. |
| Pull requests | Read and write | Leer los cambios del PR y dejar un comentario con el resultado. |
| Commit statuses | Read and write | Marcar el commit como aprobado o bloqueado. |

Nada en *Organization permissions* ni en *Account permissions*, y ningún evento suscrito. Si más adelante la App tuviera permisos de más, el panel lo avisa en rojo.

En **Where can this GitHub App be installed?** elige **Only on this account** y pulsa **Create GitHub App**.

## 2. App ID y clave privada

En la página de la App recién creada:

- **App ID**: aparece arriba, en la sección *About*.
- **Private keys → Generate a private key**: se descarga un fichero `.pem`.

## 3. Conectarla al panel

En **Integraciones → GitHub**, escribe el App ID, elige el `.pem` y pulsa **Verificar y guardar**. El panel firma un JWT con la clave y pregunta a GitHub por la App: si no casan, no guarda nada y te dice por qué. Si casan, guarda la clave **cifrada** en `config/` y muestra el nombre, la cuenta y los permisos que GitHub le atribuye.

La clave no vuelve a salir del servidor. **Borra el `.pem` de tu carpeta de descargas** cuando termines.

## 4. Instalarla en tus repositorios

Pulsa **Instalar en GitHub**, elige **Only select repositories** y marca los que quieras analizar. Vuelve al panel y pulsa **Ya la instalé** (si configuraste la Setup URL, vuelves solo). Los repositorios aparecen en **Repositorios** y en **Nuevo análisis**.

Para añadir o quitar repositorios más tarde: **Integraciones → Cambiar repositorios en GitHub**.

## Revisión de pull requests

En **Pull requests** activa la vigilancia por repositorio y elige el umbral de bloqueo. Cada pocos minutos (`APPSEC_AGENT_PR_POLL_SECONDS`) se revisan los PRs abiertos con commits nuevos: solo cuenta lo que el PR introduce frente a la rama principal. El resultado se publica como **un único comentario** que se actualiza y como un estado de commit `appsec-agent`.

## Alternativa: montar la App como secreto

Si prefieres no guardar la clave en el almacén (por ejemplo, porque ya usas un gestor de secretos), declara en el entorno del contenedor:

```bash
GITHUB_APP_ID=123456
GITHUB_APP_SLUG=tu-app          # el de github.com/apps/<slug>
GITHUB_APP_PRIVATE_KEY_FILE=/run/secrets/github-app.pem
```

El entorno manda sobre el almacén. Monta el `.pem` en solo lectura.

## Cambiar de App

**Integraciones → Usar otra GitHub App… → Olvidar la App** borra del servidor la clave y la conexión. La App sigue existiendo en GitHub: bórrala allí si ya no la usas.

## Problemas frecuentes

| Mensaje | Qué pasa |
| --- | --- |
| *GitHub no reconoce ese App ID con esa clave privada* | La clave es de otra App, o la revocaste. Genera otra en la página de la App. |
| *La clave privada debe ser RSA de al menos 2048 bits* | Has subido otro fichero; usa el `.pem` que descarga GitHub. |
| *La App todavía no está instalada en ninguna cuenta* | Falta el paso 4, o lo cancelaste en GitHub. |
| *Faltan permisos* | Cambiaste permisos en la App y la instalación no ha aceptado la actualización: acéptala en GitHub (*Settings → Applications → Installed GitHub Apps*). |
| GitHub rechaza la Setup URL | Déjala vacía y usa **Ya la instalé**; funciona igual. |
