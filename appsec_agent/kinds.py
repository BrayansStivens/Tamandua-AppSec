"""Tipos de ejecución, en un solo sitio para que ningún filtro se quede atrás al añadir uno."""

# Análisis completos de un activo: lo que no aparece en uno nuevo queda remediado.
FULL_SCANS = ("repository_scan", "image_scan")
# Avisos publicados después del último análisis, contrastados con sus dependencias (advisory_watch). Solo añaden:
# no son un análisis completo y no remedian nada.
ADVISORY_RUNS = ("advisory_watch",)
# Todo lo que alimenta el registro de hallazgos y admite triage.
FINDING_RUNS = FULL_SCANS + ("pr_review",) + ADVISORY_RUNS
