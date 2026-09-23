# Política de seguridad

## Reportar una vulnerabilidad

**No abras un issue público.** Usa el reporte privado de GitHub: pestaña **Security → Report a vulnerability** de este repositorio (GitHub Security Advisories).

Incluye, si puedes:

- versión (`/api/health` o la etiqueta del panel) y cómo lo despliegas;
- pasos para reproducirlo y el impacto que ves;
- si ya es público o explotado.

No incluyas secretos reales, tuyos ni de terceros. Respondemos en cuanto podamos; es un proyecto mantenido por voluntarios, así que no hay un plazo garantizado, pero los fallos que expongan credenciales o código tienen prioridad.

## Versiones con soporte

Solo la última versión de la rama `main`.

## Alcance

Entra en el alcance cualquier fallo del propio Tamandua: autenticación, sesiones, almacén de secretos, API, panel y ejecución de motores. Quedan fuera los fallos de las herramientas de terceros (Trivy, Gitleaks, Opengrep): repórtalos a sus proyectos. El uso del socket de Docker es una concesión documentada en [docs/seguridad.md](docs/seguridad.md#concesiones-conocidas).
