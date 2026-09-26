# Reglas SAST propias

Reglas en sintaxis Semgrep para el motor **Opengrep** (LGPL-2.1). Son nuestras y van bajo MIT: las reglas del registry de Semgrep cambiaron de licencia en diciembre de 2024 (solo uso interno, prohibido ofrecerlas como servicio) y no pueden entrar en un producto.

Criterio: **precisión sobre cobertura**. Cada regla apunta a un sumidero concreto (ejecución, SQL, deserialización, HTML sin escapar, TLS sin validar) y, cuando el lenguaje lo permite, usa análisis de taint intra-archivo desde entradas de la petición. Los patrones "argumento no literal" son de confianza media y lo declaran en `metadata.confidence`.

Severidad: `ERROR` → alta, `WARNING` → media, `INFO` → baja; `metadata.severity: CRITICAL` eleva a crítica los sumideros de ejecución remota con flujo desde la petición.

Validar: `docker run --rm --network none -v "$PWD/rules:/rules:ro" tamandua/opengrep:1.30.0 scan --validate --config /rules /rules`
