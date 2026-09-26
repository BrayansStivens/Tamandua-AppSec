# Tamandua · notas para agentes

- Idioma del código, comentarios, mensajes y commits: español.
- Antes de crear o cambiar la interfaz (`web/src`), un informe (PDF o Markdown), una exportación o el diagrama de amenazas,
  sigue la skill `.claude/skills/tamandua-design/SKILL.md`. Antes de hacer commit de esos cambios, pasa el agente
  `design-reviewer` (`.claude/agents/design-reviewer.md`).
- Compatibilidad de datos: quien actualiza ya tiene `data/`. Un cambio de formato en disco lleva lector tolerante
  y, si hay que reescribir datos, una migración en `appsec_agent/migrations.py` con su prueba
  (ver «Cambiar el formato» en `docs/desarrollo.md`). Nunca reordenar ni borrar migraciones publicadas.
- Pruebas: `make test` (backend) y `cd web && npx tsc -b && npx oxlint src` (panel).
