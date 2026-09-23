# Funcionalidades

Qué hace cada parte del panel y con qué criterio. Para instalarlo, ve a [instalacion.md](instalacion.md).

## En desarrollo

Se ven en el panel en gris, con la marca **En desarrollo**, para que se sepa que vienen. Hoy no dan resultados y no se pueden usar:

| Función | Qué hará |
| --- | --- |
| Pentest de aplicaciones web y API | Pruebas dinámicas (DAST) con ZAP o Nuclei en un contenedor aislado, solo sobre dominios cuya propiedad hayas verificado por DNS. |
| GitLab, Bitbucket, Azure DevOps | Conectar repositorios con tokens de solo lectura del proyecto. |
| Asistencia con IA | Explicación de hallazgos y propuesta de parche con tu propia clave, con consentimiento en cada ejecución. |
| API pública y CLI para CI | Tokens personales con ámbitos, `/api/v1` documentada y un comando para CI que envía los resultados a tu instancia y rompe el build según un umbral. |

## Panel

El **Resumen** se calcula a partir de las ejecuciones (`GET /api/dashboard?days=7|30|90|365`) con definiciones explícitas: *abierto* es lo que hay en la última ejecución de cada activo; *corregido* es una huella que estaba en una ejecución anterior de ese activo y ya no aparece; el tiempo medio de corrección va de la primera detección a la primera ausencia. La puntuación es un resumen con su fórmula al lado (`100·e^(−riesgo/150)`, riesgo ponderado por severidad, KEV y EPSS), no una certificación. Las gráficas son SVG sin dependencias: hallazgos nuevos por día apilados por severidad, abiertos por severidad, hallados frente a corregidos, CWE, activos más afectados, exploitabilidad (KEV y EPSS ≥ 10 %), mapa de actividad anual, y dos paneles de novedades: altas en CISA KEV y CVEs publicados en los últimos 7 días según NVD, marcando los que mencionan un paquete o CVE de tus hallazgos abiertos.

La paleta de severidad es una rampa ordinal de un solo tono validada con el validador de paleta en modo claro y oscuro; el texto nunca lleva el color de la serie.

## Cobertura OWASP

La matriz de la ejecución se calcula de lo que corrió: cuántas reglas propias apuntan a cada categoría (leídas de `rules/`), qué motores la cubrieron y cuántos hallazgos produjo. Lo que un análisis estático no cubre (diseño inseguro, registro y alertas, condiciones excepcionales) se declara con su motivo, no con una frase genérica.

## Escaneos en segundo plano

Lanzar un escaneo devuelve al instante `202` con su identificador y lo encola; un único trabajador los procesa en orden. Mientras corre, la ejecución existe con estado `queued` o `running` y un registro de progreso pensado para el usuario —qué paso empezó, qué terminó y con qué cuenta— que el panel muestra como consola en vivo y conserva plegado al terminar. El progreso nunca incluye rutas internas, salidas crudas de herramientas ni trazas: si algo falla, se dice en qué fase y que el equipo puede revisar los logs con el identificador. Al terminar, el panel avisa con un aviso flotante (y una notificación del navegador si ya diste permiso).

## Imágenes de contenedor

**Nuevo pentest → Imagen de contenedor** analiza una imagen tal como la usas en `docker pull` (`ghcr.io/acme/api:1.4`, `nginx:1.27`, `…@sha256:…`), leyéndola directamente del registro. **No se ejecuta ni se construye**, y no ocupa espacio en tu Docker.

| Qué | Cómo |
| --- | --- |
| Paquetes del sistema y de la aplicación | **Trivy y Grype**. En código fuente coinciden casi por completo, pero en imágenes discrepan en los paquetes con parches retroportados por la distribución (en `nginx:1.21`: 781 avisos en común, 99 solo de Trivy y 11 solo de Grype, uno crítico). Los avisos se fusionan por paquete, versión e identificador (CVE/GHSA); los que ven ambos suben de confianza. |
| Secretos en capas | Trivy busca credenciales en los ficheros de cada capa. |
| Credenciales en `ENV` | Variables con nombre de secreto (`*_TOKEN`, `*_PASSWORD`, `API_KEY`…) y valor fijo: cualquiera que descargue la imagen las lee con `docker inspect`. |
| Credenciales en el historial | `ARG` usados en un `RUN` (p. ej. `NPM_TOKEN=… npm ci`), URLs con usuario y contraseña y cabeceras `Authorization` fijas: quedan en la imagen y se leen con `docker history`. La corrección recomendada es `RUN --mount=type=secret` de BuildKit. |
| Configuración | Usuario root, falta de `HEALTHCHECK`, `ADD` desde una URL, SSH expuesto, etiqueta `latest` e imagen de más de un año. |

Ningún valor secreto se guarda: solo el nombre de la variable o el paso del historial. Las imágenes privadas necesitan un token de **solo lectura** del registro, que un administrador guarda en **Integraciones → Registros de contenedores** (cifrado). Cada imagen es un activo propio en **Hallazgos**, identificado por registro y repositorio, sin la etiqueta: al analizar `api:1.5`, lo que ya no aparece respecto a `api:1.4` queda remediado.

También por CLI (útil en CI): `make cli ARGS="scan-image --reference ghcr.io/acme/api:1.4"`. Devuelve `2` si hay hallazgos.

## Hallazgos y su ciclo de vida

**Hallazgos** agrupa por repositorio. Cada repositorio tiene un **registro** con el estado actual de cada hallazgo (por su huella estable), su origen, cuándo se vio por primera y por última vez y si sigue abierto. Se actualiza solo:

- **Escaneo completo** de la rama principal: lo que aparece queda abierto (y se reabre si estaba remediado); lo que estaba abierto y ya no aparece queda **remediado automáticamente**.
- **Revisión de PR**: lo que introduce el PR queda abierto con origen «PR #n»; si un commit posterior del mismo PR lo quita, queda remediado. Un PR cerrado sin merge retira sus hallazgos; uno mergeado los deja a la espera del siguiente escaneo completo.
- **Triage manual**: en curso, falso positivo, riesgo aceptado (solo administradores, con caducidad) o remediado. Salvo «en curso», todos piden un motivo, que queda en el historial con usuario y fecha. Una remediación manual que reaparece en un escaneo posterior se reabre sola.

La identidad del repositorio es la de GitHub (su id numérico): un repositorio renombrado sigue siendo el mismo, y los hallazgos de uno eliminado se retiran tras 24 horas de gracia. Se puede filtrar por ejecución, ver abiertos, remediados o todos, y exportar a JSON, Markdown, SARIF o Jira.

## CVE tracker

Busca en una copia local de NVD (`data/feeds/cves.sqlite`, SQLite con FTS5) cruzada con CISA KEV y EPSS: texto libre, CVE por prefijo, severidad, solo KEV, año, orden por fecha, CVSS o EPSS y paginación. Un hilo la carga en segundo plano de lo más reciente a lo más antiguo, reanudable tras reiniciar, y luego la mantiene al día cada 2 horas por fecha de modificación. Sin API key NVD admite 5 peticiones cada 30 s y la carga completa (~400.000 CVE) tarda unas horas; con `APPSEC_AGENT_NVD_API_KEY` (va en cabecera, nunca se registra) va unas 8 veces más rápido. `APPSEC_AGENT_CVE_SYNC=off` la desactiva. El detalle de cada CVE dice qué repositorios analizados lo tienen entre sus hallazgos.

La página muestra, para cada CVE, severidad y CVSS, EPSS, si está en CISA KEV, CWE, vector, referencias y **qué repositorios tuyos lo tienen** entre sus hallazgos. La búsqueda queda en la URL: se puede compartir o recargar. En el **Resumen**, *Novedades* muestra los publicados en 7 y 30 días y un «skyline» 3D de los últimos 30 días por severidad.

## Revisión de pull requests

**Pull requests** lista los PRs abiertos de cada repositorio de la GitHub App. Un administrador activa por repositorio **Vigilar PRs**, **Comentar y marcar el commit en GitHub** y el umbral de bloqueo (crítica, alta o superior —por defecto—, media o superior, o nunca). Sin webhooks, para que el servidor no tenga que ser accesible desde internet, un vigilante sondea cada `APPSEC_AGENT_PR_POLL_SECONDS` (300 s por defecto, mínimo 60) y encola una revisión por cada commit de cabeza nuevo; los borradores se saltan y **Revisar ahora** la lanza a mano.

La revisión escanea el commit de cabeza con los mismos motores y cuenta solo lo que el PR **introduce**:

- un hallazgo de código o secreto cuenta si cae en una línea añadida o modificada del diff; uno de dependencias, si el PR toca el manifiesto que lo declara;
- si su huella ya estaba en el último escaneo de la rama principal, es **preexistente**: se informa aparte y no se cuenta contra el PR. Sin escaneo previo se cuenta todo lo que cae en líneas cambiadas, y se dice.

El resultado queda en el panel como una ejecución más (con triage compartido con la rama principal y exportación a Jira). En GitHub se publica un **único comentario** que se reescribe en cada push —solo se edita uno creado por esta App— y un **estado de commit** `appsec-agent` que falla si el PR introduce algo del umbral o peor. Los secretos se citan por regla y ubicación; su valor nunca se publica.

**Permisos de la App.** Leer PRs y publicar exige **Pull requests: Read and write** y **Commit statuses: Read and write**, que la guía de creación ya incluye. Si cambias permisos en una App existente, acepta la actualización en *Settings → Applications → Installed GitHub Apps*; mientras tanto, el panel dice qué permiso falta en lugar de fallar en silencio.

## Modelado de amenazas

**Amenazas** guarda modelos del sistema: componentes (usuario, app web, API, servicio, función, base de datos, caché, cola, almacenamiento, tercero, proveedor de identidad), flujos de datos (protocolo, qué datos llevan, si van autenticados o cifrados) y fronteras de confianza. Cada componente puede enlazarse a un repositorio escaneado o a un dominio.

- **Propuesta desde cualquier repositorio.** Al crear un modelo eliges cualquiera de los repositorios de la GitHub App o el workspace, estén escaneados o no. Se leen en el momento solo sus manifiestos con la API de git (árbol del repositorio y blobs; basta `contents: read`, sin descargar el repositorio): `package.json`, `requirements*.txt`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `Dockerfile` y compose, hasta 40 ficheros y sin `node_modules`, fixtures ni tests. FastAPI, Next.js, Express o axum se convierten en procesos; psycopg, Prisma, Mongoose o sqlx, en bases de datos (un ORM se fusiona con su motor); Stripe, Twilio, S3, next-auth o un SDK de LLM, en terceros o proveedores de identidad. **Cada componente propuesto cita la dependencia y el fichero que lo originó** y queda marcado como propuesto para que el equipo lo corrija. Del inventario solo se guardan nombres, nunca versiones ni valores de configuración. Un repositorio sin escanear se modela igual, pero sus amenazas no tienen evidencia hasta escanearlo.
- **STRIDE con reglas propias y visibles** (`TM-S01`…`TM-E02` en `threat_model.py`). Cada amenaza dice qué la dispara en ese elemento, su severidad (base de la regla, un nivel arriba si está expuesto y lleva credenciales o pagos, uno abajo si es interno y poco sensible), sus mitigaciones y sus CWE.
- **Evidencia.** Si el repositorio de un componente, o el de los procesos que lo usan, tiene hallazgos abiertos con uno de esos CWE, la amenaza pasa a **evidenciada** y enlaza a ellos. Los avisos de dependencias evidencian «dependencias vulnerables», no la inyección en tu código. Lo descartado en triage no cuenta.
- **Decisiones** por amenaza (mitigada, aceptada, no aplica) con motivo, autor y fecha.
- **Exportaciones**: JSON de OWASP Threat Dragon v2, script de OWASP pytm (`tm.py`, para quien siga modelando como código) e informe Markdown. La estructura del JSON sigue el formato v2, pero no se ha probado su importación en Threat Dragon.

## Jira

Un administrador conecta **Jira Cloud** en **Integraciones** con el sitio, el email, un [API token de Atlassian](https://id.atlassian.com/manage-profile/security/api-tokens), la clave del proyecto y el tipo de incidencia. Antes de guardar se comprueba la cuenta, el proyecto y que el tipo exista. El token se guarda cifrado en el almacén de `config/` y nunca vuelve al navegador: se ven el email, el proyecto y sus cuatro últimos caracteres.

Solo se aceptan sitios `https://<sitio>.atlassian.net` y no se siguen redirecciones, de modo que el panel no puede usarse para lanzar peticiones a otros destinos. Jira Server/Data Center queda fuera a propósito: exigiría aceptar hosts arbitrarios de la red del cliente.

En la tabla de hallazgos, **Crear en Jira** convierte la selección en incidencias (hasta 50 hallazgos por vez; lo descartado en triage no se exporta). Se crea **una incidencia por trabajo de remediación**: los avisos de un mismo paquete van juntos con la versión que los cierra todos, y el código y los secretos van uno a uno. Cada incidencia lleva la etiqueta `appsec-<huella>` de cada hallazgo que cubre. Antes de crear se busca por esas etiquetas y el vínculo se recuerda por repositorio y huella (`data/jira-links.json`), así que volver a exportar —hoy o tras el próximo escaneo— enlaza la incidencia existente en lugar de duplicarla. Si el proyecto no admite fijar la prioridad al crear, se reintenta sin ella.

## Motores de análisis

La revisión de código corre tres motores externos, cada uno en su contenedor pinneado por digest, sin capacidades, sin escalada de privilegios y con el snapshot montado en solo lectura:

| Motor | Frente | Red | Imagen |
| --- | --- | --- | --- |
| **Trivy 0.74.0** | dependencias de cualquier ecosistema, configuración de infraestructura (Dockerfile, Kubernetes, Terraform) y secretos | solo para bajar su base de vulnerabilidades, cacheada en `data/trivy-cache/`; no envía nada del repositorio | `aquasec/trivy@sha256:62b1e65e…` |
| **Gitleaks 8.30.1** | secretos, alta precisión, valores redactados | ninguna | `ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0…` |
| **Opengrep 1.30.0** | SAST con **reglas propias** (`rules/`, MIT) para JavaScript, TypeScript, Python, Java, Go, PHP, Ruby y C# | ninguna | `appsec-agent/opengrep:1.30.0`, construida localmente |

La imagen de Opengrep la construye `make build` (o `make up`): descarga el binario oficial y lo compara con su SHA-256 fijado (la verificación Cosign está documentada en `containers/opengrep/VERIFY.md`).

Las reglas son nuestras porque las del registry de Semgrep no pueden usarse en un producto (licencia de uso interno desde diciembre de 2024). Son 58, orientadas a sumideros concretos con análisis de taint donde el lenguaje lo permite, y se validan contra `fixtures/sast-samples/`: las 58 disparan sobre código vulnerable de los siete lenguajes. Cada paso declara qué lenguajes del repositorio tienen reglas y cuáles no. No hay análisis entre archivos: es una limitación de todo SAST open source y se dice en los límites de cada ejecución.

Si Docker no está disponible, el paso lo declara como `not_tested` con el motivo y la revisión sigue con las reglas internas de Python y los patrones de secretos, etiquetados como tales. Cuando Trivy resuelve las dependencias, OSV no se consulta: menos egress y sin enviar nombres de paquetes a nadie.

## Hallazgos de dependencias

Cada aviso de dependencia llega listo para decidir, no como un identificador suelto. Del detalle de OSV se toman resumen, alias CVE/GHSA, CWE y el vector CVSS, cuyo **score se calcula** con la fórmula 3.1 en lugar de copiarse. La **versión corregida** se elige del rango que contiene la versión instalada: quien usa `minimatch 9.0.5` oye "actualiza a 9.0.6", no "a 10.2.3". Se cruza con dos feeds públicos descargados en bloque y guardados a diario en `data/feeds/` —el catálogo **CISA KEV** de explotación activa y las probabilidades **EPSS**—, de modo que nadie recibe consultas CVE por CVE que revelen qué dependencias tienen los clientes.

Con eso, cada hallazgo trae una **prioridad con sus factores visibles** (`act` si está en KEV o combina CVSS ≥ 9 con EPSS alto; `attend`; `track`), una remediación concreta y una **huella estable** independiente de la ruta del lockfile, que es lo que evitará duplicar tickets entre ejecuciones. El panel agrupa los avisos por paquete y dice qué versión los cierra todos; `GET /api/runs/{id}/tickets.json` exporta un ticket por hallazgo con esa forma, pensado para el conector de Jira.

Si el propietario autoriza transmitir **solo nombres y versiones de dependencias** a `api.osv.dev`, activa la casilla del panel para esa ejecución o usa `--allow-osv-upload` en la CLI. Por defecto SCA aparece como `not_tested`. Una consulta inconclusa tampoco se presenta como cero vulnerabilidades.

```bash
python3 -m appsec_agent scan-repository --source-id local:appsec-agent --allow-osv-upload
```

Los informes JSON, Markdown, SARIF, SOC 2 Tipo II e ISO 27001 se descargan desde cada ejecución. Los perfiles de cumplimiento ordenan evidencia técnica; no constituyen auditoría, certificación ni atestación. Los enlaces CWE/CVE/GHSA apuntan a los registros públicos correspondientes cuando hay identificadores. DAST sobre objetivos reales sigue pendiente.

## Proveedores de IA

Cada usuario puede guardar su propia clave de OpenAI o Anthropic en **Integraciones**; se comprueba contra el catálogo de modelos del proveedor sin enviar código ni hallazgos. Hoy la IA **no participa** en el análisis: cuando lo haga, será opcional y con consentimiento en cada ejecución.

```bash
make cli ARGS="providers"
make cli ARGS="ai-check --provider openai"
```

La CLI devuelve `0` sin hallazgos, `2` con hallazgos, `3` si el análisis quedó incompleto y `1` ante una entrada inválida.
