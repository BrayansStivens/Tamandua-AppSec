# Tamandua · notes for agents

- **Language.** Code, identifiers and comments in English; keep comments few (only the non-obvious why). Commit
  messages in Spanish. Skills and agents (`.claude/`, `skills/`) in English.
- **User-facing text** exists in English (source) and Spanish, through the i18n catalogs: follow
  `.claude/skills/tamandua-i18n/SKILL.md` ("interpret, don't translate"; stored text is language-neutral). Use the
  `i18n-localizer` agent for localization work.
- **Design.** Before creating or changing the panel (`web/src`), a report (PDF or Markdown), an export or the threat
  diagram, follow `.claude/skills/tamandua-design/SKILL.md`, and run the `design-reviewer` agent before committing.
- **Data.** All state lives in PostgreSQL (tables per context in `modules/<ctx>/tables.py`; settings in
  `shared/documents.py`). A schema change needs an Alembic migration; rewriting data, a migration in
  `tamandua/app/data_migrations.py` with its test. Never reorder or delete published migrations.
- **Architecture.** Modular monolith in `tamandua/` (see `docs/architecture.md`). Business code in
  `tamandua/modules/<context>/`; `modules` never imports `app`/`cli`, `shared` never imports `modules`, and the
  business code never imports FastAPI/Starlette. `make arch` (import-linter) enforces it. Discuss a new context or a new
  cross-context dependency first.
- **Panel.** By feature in `web/src/{app,pages,features,shared}` (a layer never imports from the layers above;
  `tests/test_web_layers.py`). Server data with TanStack Query (`shared/api/queries.ts`), no loose `setInterval` or
  `fetch` for new code.
- **API.** New routes in FastAPI (`tamandua/app/api/<context>.py`) with Pydantic schemas and `guard(Policy(...))`. After changing a route:
  `make openapi` (the panel uses the generated types in `web/src/shared/api/`; CI checks they are current).
- **Checks.** `make test` and `make arch` (backend) and `cd web && npx tsc -b && npx oxlint src` (panel).
