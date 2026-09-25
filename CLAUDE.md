# Tamandua · notas para agentes

- Idioma del código, comentarios, mensajes y commits: español.
- Antes de crear o cambiar la interfaz (`web/src`), un informe (PDF o Markdown), una exportación o el diagrama de amenazas,
  sigue la skill `.claude/skills/tamandua-design/SKILL.md`. Antes de hacer commit de esos cambios, pasa el agente
  `design-reviewer` (`.claude/agents/design-reviewer.md`).
- Pruebas: `make test` (backend) y `cd web && npx tsc -b && npx oxlint src` (panel).
