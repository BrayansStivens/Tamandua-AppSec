# Inicio rápido

De cero a ver un hallazgo corregido y verificado, en unos 15 minutos. Los pasos marcados **opcional** se
pueden dejar para después.

## 1. Arrancar (5 min)

Necesitas Docker (Engine 24+ con Compose v2.24+), `make` y `git`. `make doctor` comprueba que todo está.

```bash
git clone https://github.com/BrayansStivens/appsec-agent.git
cd appsec-agent
make up
```

La primera vez descarga los motores (unos minutos). Al terminar muestra la URL (<http://127.0.0.1:8766>) y un
**código de configuración** de un solo uso: con él creas el administrador en el panel. Si lo pierdes,
`make setup-code` lo vuelve a mostrar.

Después, en **Cuenta**, activa el segundo factor.

## 2. Verlo funcionar sin conectar nada (2 min)

```bash
make demo
```

Analiza de verdad, con los mismos motores del panel, los ejemplos vulnerables a propósito que trae el
repositorio (código en siete lenguajes, dependencias con CVE, un secreto y un Dockerfile) e importa un modelo
de amenazas de ejemplo. En el panel verás el activo **«demo · ejemplos vulnerables»**:

- **Resumen:** hallazgos por severidad, explotación activa (KEV) y lo que hay que atender primero.
- **Hallazgos:** despliega uno y mira **Cómo corregirlo** (el comando o el ejemplo de código). «Reverificar» funciona en tus repositorios.
- **Amenazas:** el diagrama, las amenazas y el informe PDF.

Con `make demo IMAGE=nginx:1.21` también se analiza una imagen pública (Trivy + Grype, un par de minutos).

## 3. Conectar tus repositorios de GitHub (5 min)

En **Integraciones → Proveedores de código**, el panel te guía para crear la GitHub App de tu servidor con
los permisos justos (lectura de código, comentarios y estados en PRs). Al final la instalas en los
repositorios que quieras: mejor *Only select repositories* para empezar. Detalle en [github-app.md](github-app.md).

Sin GitHub (GitLab, Bitbucket, Azure DevOps o una carpeta local): usa [`scan` en la terminal o en CI](cli.md).

## 4. Primer análisis y primera corrección

1. **Nuevo análisis → Análisis de código**, elige uno o varios repositorios (o una organización entera) y lanza.
2. En **Hallazgos**, empieza por lo marcado como KEV o crítico. Cada hallazgo trae **Cómo corregirlo**.
3. Aplica la corrección, súbela a la rama principal y pulsa **Reverificar**: al terminar el análisis te dice
   «Corregido ✓» o «Sigue presente».

Si decides no corregir algo, regístralo en el triage (riesgo aceptado o falso positivo) con su motivo y una
fecha de caducidad: queda como evidencia y no vuelve a molestar.

## 5. Que trabaje solo (opcional, recomendado)

- **Pull requests y rama principal:** en **Pull requests**, un administrador activa la vigilancia de tus repositorios. Cada PR se
  revisa solo (solo cuenta lo que introduce) y, tras un merge, la rama principal se reanaliza.
- **Avisos nuevos a diario:** activos por defecto. Una vez al día se contrastan tus dependencias con los
  avisos publicados después del último análisis, sin conexión.
- **Avisos a tu canal:** en **Integraciones → Avisos**, añade Slack, Teams o un webhook para enterarte sin abrir
  el panel. Para que los mensajes enlacen al hallazgo, define `TAMANDUA_PUBLIC_URL`.

## 6. Más adelante (opcional)

- **Equipo:** invita a más personas en **Usuarios** (rol miembro o administrador).
- **Jira:** en **Integraciones**, para convertir hallazgos en incidencias sin duplicados.
- **Imágenes privadas:** credenciales de solo lectura en **Integraciones → Registros de contenedores**.
- **Auditorías:** en Hallazgos, **Más formatos → Evidencia para auditoría (SOC 2, ISO)…** genera el PDF (o **Informe de los seleccionados** con los que marques).
- **Desde otra máquina:** ponlo detrás de HTTPS (ver el README); sin HTTPS fuera de `127.0.0.1` no arranca.

¿Algo no funciona? [solucion-problemas.md](solucion-problemas.md) o `make doctor`.
