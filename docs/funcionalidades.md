# Funcionalidades

Qué hace cada parte del panel y con qué criterio. Para instalarlo, ve a [instalacion.md](instalacion.md).

**Vocabulario.** Tamandua hace **análisis**: lee el código, las dependencias, la configuración y las imágenes sin ejecutarlos ni atacar nada, y sus hallazgos son candidatos que hay que confirmar. No es un *pentest*: un pentest intenta explotar los fallos contra un sistema en marcha y demuestra el impacto. Las futuras **pruebas dinámicas** (DAST) serán escaneos activos, tampoco un pentest; solo cuando un agente intente explotar y confirme el impacto hablaremos de *pentest asistido por IA*. Un informe de Tamandua no sustituye al pentest que piden SOC 2 o ISO 27001.

## En desarrollo

Se ven en el panel en gris, con la marca **En desarrollo**, para que se sepa que vienen. Hoy no dan resultados y no se pueden usar:

| Función | Qué hará |
| --- | --- |
| Pruebas dinámicas de aplicaciones web y API | Escaneo activo (DAST) con ZAP o Nuclei en un contenedor aislado, solo sobre dominios cuya propiedad hayas verificado por DNS. |
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

**Nuevo análisis → Imagen de contenedor** analiza una imagen tal como la usas en `docker pull` (`ghcr.io/acme/api:1.4`, `nginx:1.27`, `…@sha256:…`), leyéndola directamente del registro. **No se ejecuta ni se construye**, y no ocupa espacio en tu Docker.

| Qué | Cómo |
| --- | --- |
| Paquetes del sistema y de la aplicación | **Trivy y Grype**. En código fuente coinciden casi por completo, pero en imágenes discrepan en los paquetes con parches retroportados por la distribución (en `nginx:1.21`: 781 avisos en común, 99 solo de Trivy y 11 solo de Grype, uno crítico). Los avisos se fusionan por paquete, versión e identificador (CVE/GHSA); los que ven ambos suben de confianza. |
| Secretos en capas | Trivy busca credenciales en los ficheros de cada capa. |
| Credenciales en `ENV` | Variables con nombre de secreto (`*_TOKEN`, `*_PASSWORD`, `API_KEY`…) y valor fijo: cualquiera que descargue la imagen las lee con `docker inspect`. |
| Credenciales en el historial | `ARG` usados en un `RUN` (p. ej. `NPM_TOKEN=… npm ci`), URLs con usuario y contraseña y cabeceras `Authorization` fijas: quedan en la imagen y se leen con `docker history`. La corrección recomendada es `RUN --mount=type=secret` de BuildKit. |
| Configuración | Reglas propias: usuario root, falta de `HEALTHCHECK`, `ADD` desde una URL, SSH expuesto, etiqueta `latest` e imagen de más de un año. |
| Instrucciones del historial | **Checkov** sobre un Dockerfile reconstruido a partir del historial de la imagen: descargas con TLS desactivado (`curl -k`, `wget --no-check-certificate`, `NODE_TLS_REJECT_UNAUTHORIZED=0`), `pip --trusted-host`, gestores de paquetes sin firma, `sudo`, `chpasswd`… Cada hallazgo apunta al paso del historial. El modo de imágenes propio de Checkov necesita una cuenta de Prisma Cloud, por eso se reconstruye el Dockerfile. |

Ningún valor secreto se guarda: solo el nombre de la variable o el paso del historial. Las imágenes privadas necesitan un token de **solo lectura** del registro, que un administrador guarda en **Integraciones → Registros de contenedores** (cifrado). Cada imagen es un activo propio en **Hallazgos**, identificado por registro y repositorio, sin la etiqueta: al analizar `api:1.5`, lo que ya no aparece respecto a `api:1.4` queda remediado.

También por CLI (útil en CI): `make cli ARGS="scan-image --reference ghcr.io/acme/api:1.4"`. Devuelve `2` si hay hallazgos.

## Hallazgos y su ciclo de vida

**Hallazgos** agrupa por repositorio. Cada repositorio tiene un **registro** con el estado actual de cada hallazgo (por su huella estable), su origen, cuándo se vio por primera y por última vez y si sigue abierto. Se actualiza solo:

- **Escaneo completo** de la rama principal: lo que aparece queda abierto (y se reabre si estaba remediado); lo que estaba abierto y ya no aparece queda **remediado automáticamente**.
- **Revisión de PR**: lo que introduce el PR queda abierto con origen «PR #n»; si un commit posterior del mismo PR lo quita, queda remediado. Un PR cerrado sin merge retira sus hallazgos; uno mergeado los deja a la espera del siguiente escaneo completo.
- **Triage manual**: en curso, falso positivo, riesgo aceptado (solo administradores, con caducidad) o remediado. Salvo «en curso», todos piden un motivo, que queda en el historial con usuario y fecha. Una remediación manual que reaparece en un escaneo posterior se reabre sola.

### Rutas excluidas

Hay carpetas que no conviene mirar: ejemplos vulnerables a propósito (como `fixtures/` en este mismo proyecto), pruebas con datos falsos o código generado. Un **administrador** las excluye por repositorio en **Hallazgos → Rutas excluidas**, una por línea (`fixtures/**`, `docs/*.md`, `**/testdata/**`; `*` no cruza carpetas, `**` sí), con un motivo obligatorio que queda en el historial.

- Lo que cae en ellas no cuenta como abierto, no entra en el informe ni en el SARIF y **no bloquea PRs**. No desaparece: queda en la pestaña **Excluidos** y cada ejecución dice en sus límites cuántos hallazgos quedaron fuera y por qué patrón.
- Excluir no es remediar: lo excluido nunca pasa a «remediado». Si se quita la exclusión, vuelve a abierto.
- Las exclusiones viven en el servidor (`data/exclusions.json`), **no en el repositorio**: un fichero en el repositorio permitiría que un PR se excluyera a sí mismo. Por la misma razón no se aplica el `.gitleaks.toml` del repositorio.
- No se admiten patrones que lo excluyan todo (`**`, `*/**`), rutas absolutas ni `..`.

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

- **Cada modelo es un proyecto.** Se crea con un nombre y un enfoque; no necesita repositorios. Los **repositorios del proyecto** se asocian cuando se quiera, uno o varios (microservicios, microfrontends), y un componente enlazado a un repositorio lo añade solo a la lista.
- **Propuesta desde cualquier repositorio, en cualquier momento.** Al crear el proyecto (opcional) o después, desde cada repositorio asociado, se proponen componentes y flujos que se **suman al diagrama sin duplicar** lo que ya hay y respetando lo que el equipo dibujó (lo nuevo entra en su frontera o a la derecha). Sirven los repositorios de la GitHub App o del workspace, estén escaneados o no. Se leen en el momento solo sus manifiestos con la API de git (árbol del repositorio y blobs; basta `contents: read`, sin descargar el repositorio): `package.json`, `requirements*.txt`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `Dockerfile` y compose, hasta 40 ficheros y sin `node_modules`, fixtures ni tests. FastAPI, Next.js, Express o axum se convierten en procesos; psycopg, Prisma, Mongoose o sqlx, en bases de datos (un ORM se fusiona con su motor); Stripe, Twilio, S3, next-auth o un SDK de LLM, en terceros o proveedores de identidad. **Cada componente propuesto cita la dependencia y el fichero que lo originó** y queda marcado como propuesto para que el equipo lo corrija. Del inventario solo se guardan nombres, nunca versiones ni valores de configuración. Un repositorio sin escanear se modela igual, pero sus amenazas no tienen evidencia hasta escanearlo.
- **Reglas propias y visibles** (STRIDE `TM-S01`…`TM-E02` en `threat_model.py`, LINDDUN `PV-*` en `threat_methods.py`). Cada amenaza dice qué la dispara en ese elemento, su severidad (base de la regla, un nivel arriba si está expuesto y lleva credenciales o pagos, uno abajo si es interno y poco sensible), sus mitigaciones y sus CWE.
- **Enfoques.** Cada modelo elige cómo se analiza, y se puede cambiar sin perder el diagrama:

  | Enfoque | Para qué | Qué hace Tamandua |
  | --- | --- | --- |
  | STRIDE | Amenazas de seguridad en componentes y flujos | Reglas propias sobre el diagrama (`TM-*`) |
  | LINDDUN | Amenazas a la privacidad de las personas | Reglas propias sobre los elementos con datos personales (`PV-*`) |
  | PASTA | Riesgo para el negocio en siete etapas | Etapas con notas; la 3, la 4 y la 5 se alimentan del diagrama, de STRIDE y de los análisis |
  | Árboles de ataque | Rutas hacia un objetivo del atacante | Editor de árboles Y/O con dificultad, elemento y mitigación; calcula qué rutas siguen abiertas |
  | MITRE ATT&CK | Técnicas de atacantes reales | Selección de técnicas (web, API, contenedores, nube) para mapear a componentes, con sugerencias y enlace a attack.mitre.org |
  | Personalizado | El método de tu equipo | Diagrama permanente y selección libre de reglas STRIDE/LINDDUN, amenazas propias, etapas PASTA, árboles, ATT&CK y tabla; se guarda con el modelo |

  En cualquier enfoque se pueden **añadir amenazas propias** (escenario, categoría, elemento, severidad, posibilidad, impacto, responsable y mitigación). Cada enfoque tiene una **guía de consulta** —qué significa cada letra, las etapas, cómo se construye un árbol— que se abre a demanda al lado del trabajo y recuerda si la dejaste abierta; las categorías muestran su pregunta al pasar el ratón.
- **Editor de diagramas.** En **Diagrama** se arrastran los componentes, se crean flujos uniendo sus puntos y las fronteras de confianza son cajas que se mueven (llevándose sus componentes) y se redimensionan; un componente pertenece a la frontera en la que está su centro. Al pulsar un elemento se editan nombre, tipo, tecnología, descripción, datos y propiedades en el panel lateral. Además del catálogo, se puede crear un **tipo propio** con nombre libre y un rol base que determina qué reglas automáticas le corresponden. Las posiciones se guardan con el modelo y las usan las exportaciones. **Tabla** sigue disponible para editar muchos elementos a la vez.
- **Indicios, no confirmaciones.** Si el código de un componente tiene hallazgos abiertos con uno de esos CWE, la amenaza aparece **con indicios** y enlaza a ellos: es una señal para revisar, no la prueba de que el escenario sea explotable. Indica la **carpeta** del componente dentro del repositorio (p. ej. `frontend/`) para que en un monorepo solo cuenten los hallazgos de su código; sin carpeta cuenta el repositorio entero y la amenaza lo dice. Lo que está en rutas excluidas tampoco cuenta. Los avisos de dependencias evidencian «dependencias vulnerables», no la inyección en tu código. Lo descartado en triage no cuenta.
- **Decisiones** por amenaza (mitigada, aceptada, no aplica) con motivo, autor y fecha.
- **Importación y exportación propias**: desde la lista, **Importar JSON** abre un asistente con seis ejemplos completos (uno por enfoque), editor para pegar o modificar JSON, carga de archivo, descarga y copia del ejemplo, instrucciones para un LLM y validación previa que no crea ningún modelo. Solo se habilita **Importar modelo** tras una validación correcta del texto actual. Desde el editor se descarga **Modelo JSON** (`model.json`). Incluye el diagrama completo (posiciones, componentes, flujos y fronteras), enfoque, módulos personalizados, amenazas escritas por el equipo, etapas PASTA, árboles y técnicas ATT&CK. Sirve para editarlo a mano o pedir a un LLM que lo genere. Admite tanto el sobre `{"format":"appsec-agent-threat-model","version":1,"model":{...}}` que descarga la app como un objeto de modelo directamente. Los repositorios y dominios del archivo se guardan como `repository_refs` y `asset_ref`: **son referencias pendientes, nunca enlaces automáticos**. No hace falta que existan al importar; se pueden vincular después en el editor. Los IDs de la instancia, decisiones y hallazgos de escaneos no viajan en el formato portátil. Ejemplo mínimo:
- **Colocación del diagrama.** En el JSON, `position` (componentes), `size` (componentes redimensionados) y `box` (fronteras) son **opcionales**: sin ellos el editor coloca todo solo, por capas (actores → aplicaciones → APIs y servicios → datos y terceros) y con cada frontera como un bloque que contiene a sus componentes. Si un JSON trae posiciones que no encajan con sus fronteras (una caja más pequeña que sus componentes o dos cajas que se pisan), se recoloca al importar y la vista previa lo avisa. **Ordenar** aplica esa misma colocación en cualquier momento. Las fronteras se redimensionan arrastrando cualquier borde o esquina, y los componentes desde sus tiradores al seleccionarlos. Los tipos que no están en la lista se crean con **Otro tipo (lo nombras tú)**, eligiendo el rol base con el que se analizan.

  ```json
  {
    "name": "Portal de clientes",
    "methodology": "custom",
    "custom_modules": ["stride", "trees", "manual"],
    "repository_refs": ["equipo/portal"],
    "components": [
      {"id": "usuario", "name": "Cliente", "kind": "actor"},
      {"id": "api", "name": "API", "kind": "api", "asset_ref": "equipo/portal", "data": ["pii"]}
    ],
    "flows": [{"id": "login", "source": "usuario", "target": "api", "protocol": "https", "authenticated": false}],
    "boundaries": [{"id": "servidor", "name": "Servidor", "components": ["api"]}]
  }
  ```

  El diagrama base es común a todos los enfoques. Las secciones específicas sí se validan: STRIDE y LINDDUN admiten amenazas propias; PASTA admite sus etapas y árboles; Árboles admite árboles; ATT&CK admite técnicas. **Personalizado** admite cualquier combinación, pero cada sección debe tener su módulo activado en `custom_modules`. Un JSON incompatible se rechaza con un mensaje que indica qué sección sobra y sugiere elegir otro enfoque o personalizado. Al exportar un enfoque fijo solo se incluyen sus secciones activas; los datos de otro enfoque que puedan quedar guardados tras cambiar de plantilla no se mezclan en ese archivo.

- **Otras exportaciones**: el diagrama por separado en SVG (`diagram.svg`, con cambios pendientes guardados antes de descargar), JSON de OWASP Threat Dragon v2, script de OWASP pytm (`tm.py`, para quien siga modelando como código) e informe Markdown. La estructura del JSON de Threat Dragon sigue el formato v2, pero no se ha probado su importación en Threat Dragon.

## Jira

Un administrador conecta **Jira Cloud** en **Integraciones** con el sitio, el email, un [API token de Atlassian](https://id.atlassian.com/manage-profile/security/api-tokens), la clave del proyecto y el tipo de incidencia. Antes de guardar se comprueba la cuenta, el proyecto y que el tipo exista. El token se guarda cifrado en el almacén de `config/` y nunca vuelve al navegador: se ven el email, el proyecto y sus cuatro últimos caracteres.

Solo se aceptan sitios `https://<sitio>.atlassian.net` y no se siguen redirecciones, de modo que el panel no puede usarse para lanzar peticiones a otros destinos. Jira Server/Data Center queda fuera a propósito: exigiría aceptar hosts arbitrarios de la red del cliente.

En la tabla de hallazgos, **Crear en Jira** convierte la selección en incidencias (hasta 50 hallazgos por vez; lo descartado en triage no se exporta). Se crea **una incidencia por trabajo de remediación**: los avisos de un mismo paquete van juntos con la versión que los cierra todos, y el código y los secretos van uno a uno. Cada incidencia lleva la etiqueta `appsec-<huella>` de cada hallazgo que cubre. Antes de crear se busca por esas etiquetas y el vínculo se recuerda por repositorio y huella (`data/jira-links.json`), así que volver a exportar —hoy o tras el próximo escaneo— enlaza la incidencia existente en lugar de duplicarla. Si el proyecto no admite fijar la prioridad al crear, se reintenta sin ella.

## Motores de análisis

La revisión de código corre cinco motores externos, cada uno en su contenedor pinneado por digest, sin capacidades, sin escalada de privilegios y con el snapshot montado en solo lectura:

| Motor | Frente | Red | Imagen |
| --- | --- | --- | --- |
| **Trivy 0.74.0** | dependencias de cualquier ecosistema, configuración de infraestructura (Dockerfile, Kubernetes, Terraform) y secretos | solo para bajar su base de vulnerabilidades, cacheada en `data/trivy-cache/`; no envía nada del repositorio | `aquasec/trivy@sha256:62b1e65e…` |
| **Gitleaks 8.30.1** | secretos, alta precisión, valores redactados | ninguna | `ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0…` |
| **Opengrep 1.30.0** | SAST con **reglas propias** (`rules/`, MIT) para JavaScript, TypeScript, Python, Java, Go, PHP, Ruby y C# | ninguna | `appsec-agent/opengrep:1.30.0`, construida localmente |
| **Checkov 3.3.19** | infraestructura como código (Terraform, CloudFormation, Kubernetes, Helm, Kustomize, ARM, Bicep, Serverless, OpenAPI, Ansible, Dockerfile) y pipelines (GitHub Actions, GitLab CI, Bitbucket, Azure Pipelines, CircleCI, Argo) | ninguna (`--skip-download`, sin módulos externos) | `bridgecrew/checkov@sha256:d3e96ada…` |
| **zizmor 1.30.1** | GitHub Actions a fondo: inyección en plantillas, disparadores peligrosos (`pull_request_target`), permisos del token, acciones sin fijar por SHA o archivadas, credenciales que persisten tras `checkout` | ninguna (`--offline`) | `ghcr.io/zizmorcore/zizmor@sha256:a2eb396d…` |

La imagen de Opengrep la construye `make build` (o `make up`): descarga el binario oficial y lo compara con su SHA-256 fijado (la verificación Cosign está documentada en `containers/opengrep/VERIFY.md`).

Las reglas son nuestras porque las del registry de Semgrep no pueden usarse en un producto (licencia de uso interno desde diciembre de 2024). Son 58, orientadas a sumideros concretos con análisis de taint donde el lenguaje lo permite, y se validan contra `fixtures/sast-samples/`: las 58 disparan sobre código vulnerable de los siete lenguajes. Cada paso declara qué lenguajes del repositorio tienen reglas y cuáles no. No hay análisis entre archivos: es una limitación de todo SAST open source y se dice en los límites de cada ejecución.

### Varios motores, un solo hallazgo

Trivy y Checkov revisan la misma infraestructura y se solapan en muchas reglas, igual que Checkov y zizmor en GitHub Actions. Cuando dos motores ven **el mismo problema en el mismo sitio** (mismo archivo, líneas que se solapan y regla equivalente) queda **un único hallazgo**: el del motor principal, con «Detectado por Trivy y Checkov», las reglas equivalentes a la vista y un punto más de confianza. Lo que solo ve uno se añade tal cual.

| Frente | Manda | Suma |
| --- | --- | --- |
| Infraestructura como código | Trivy | Checkov |
| GitHub Actions y otros pipelines | zizmor | Checkov |
| Configuración de imágenes | reglas propias | Trivy y Checkov |

La equivalencia entre reglas es una tabla medida sobre repositorios vulnerables de referencia (TerraGoat, CfnGoat, KubernetesGoat y CI/CD-Goat) y revisada pareja por pareja; cuando la tabla no conoce la pareja se comparan los títulos. Medido en esos repositorios, Checkov añade entre un 39 % más de fallos (Kubernetes) y más del doble (Terraform) sobre lo que ya encuentra Trivy:

| Repositorio | Trivy | Checkov | Se unen | Nuevos de Checkov | zizmor |
| --- | --- | --- | --- | --- | --- |
| TerraGoat (Terraform) | 244 | 472 | 196 | 276 | 13 |
| KubernetesGoat (Kubernetes, Helm) | 321 | 349 | 225 | 124 | 0 |
| CfnGoat (CloudFormation) | 67 | 70 | 42 | 28 | 9 |
| CI/CD-Goat (pipelines) | 45 | 90 | 69 | 21 | 209 |

La edición libre de Checkov no trae severidad (la da su plataforma de pago). Para las reglas con pareja en Trivy se usa la de Trivy; para el resto, una regla visible en el código (`checkov_severity`): exposición pública, privilegios, credenciales o TLS desactivado suben a alta; etiquetas, monitorización, copias o claves gestionadas por el cliente bajan a baja; lo demás queda en media. zizmor sí da severidad; «acción sin fijar por SHA» se rebaja a media porque explotarla exige comprometer antes la acción de terceros.

Ni Checkov ni zizmor guardan fragmentos de código en el informe: solo regla, archivo y líneas, porque el fragmento puede contener un secreto.

Si Docker no está disponible, el paso lo declara como `not_tested` con el motivo y la revisión sigue con las reglas internas de Python y los patrones de secretos, etiquetados como tales. Cuando Trivy resuelve las dependencias, OSV no se consulta: menos egress y sin enviar nombres de paquetes a nadie.

## Hallazgos de dependencias

Se revisan también las **dependencias de desarrollo** (`devDependencies`, grupos de desarrollo), marcadas como tales: no llegan a producción, pero se ejecutan en los equipos y en la CI, que es donde golpean los ataques de cadena de suministro. Bajan un nivel de prioridad salvo que estén en CISA KEV. Para el código basta con Trivy: medido en repositorios reales, Grype encuentra lo mismo una vez incluidas las de desarrollo (Grype sí se usa en imágenes de contenedor, donde aporta).

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
