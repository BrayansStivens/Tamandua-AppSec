English · [Español](es/desarrollo.md)

# Development

For contributing, or for running Tamandua without containers. Read [CONTRIBUTING.md](../CONTRIBUTING.md) too.

## Without containers

You need Python 3.12+ and Node 22. Without Docker the engines (Trivy, Gitleaks, Opengrep) don't run: the panel says so on every scan.

```bash
make dev-setup   # .venv with the Python dependencies, plus the panel's node_modules
make web         # builds the panel into tamandua/app/static/
make dev         # server on http://127.0.0.1:8767 with its data in .dev/ (leaves Docker's data alone)
make check       # backend tests and architecture contracts + panel types and lint
```

`make dev` uses port 8767 and the `.dev/` folder so it can run next to the Docker instance. For hot reload of the panel, `cd web && npm run dev` (Vite forwards `/api` to the backend).

The CLI uses the same store as the panel (in Docker: `make cli ARGS="…"`):

```bash
.venv/bin/python -m tamandua --data-dir .dev/data sources
.venv/bin/python -m tamandua --data-dir .dev/data scan-repository --source-id github:org/repo
.venv/bin/python -m tamandua --data-dir .dev/data runs
```

## API pagination

`GET /api/runs/page?limit&offset&status&type&q` filters, counts and paginates in PostgreSQL over each run's lightweight row (the `row` column of `runs`); a thousand runs never means loading a thousand records with their findings. The panel uses the same pagination hook for the scan list, the run picker and the findings table.

## Logs

Logs go to standard error, human-readable by default or one JSON object per event with `TAMANDUA_LOG_FORMAT=json` (time, level, component, run ID, method, path, status, duration). `TAMANDUA_LOG_FILE=logs/app.log` also keeps a JSON copy under the data folder, rotated at 10 MB × 5 (Compose sets it). Set `TAMANDUA_LOG_LEVEL=DEBUG` to debug. Bodies, headers and tokens are never logged, and `redact()` masks credential patterns that might slip into a message.

## Development and tests

The React/TypeScript frontend uses [shadcn/ui](https://ui.shadcn.com/docs/installation/vite), Tailwind and Lucide. The theme picker is a shadcn component; it supports system, light and dark (dark by default).

```bash
cd web
npm ci
npm run build
npm run lint
cd ..
.venv/bin/python -m unittest discover -s tests -v
```

The tests need PostgreSQL: `make test` starts a throwaway one in Docker (data in memory) and gives each test its own schema (`TAMANDUA_DB_ISOLATE=data-dir`). To run a single file: `TAMANDUA_DATABASE_URL=$(sh scripts/test-db.sh) TAMANDUA_DB_ISOLATE=data-dir TAMANDUA_CONFIG_DIR=$(mktemp -d) .venv/bin/python -m unittest discover -s tests -p 'test_x.py'` (the temporary configuration folder keeps the tests from creating a master key in yours). `make lint-py` runs ruff and mypy, and `make arch` the architecture contracts; CI runs all three. mypy skips the modules listed in `pyproject.toml`, which had type errors when it arrived: fixing one means taking it off the list.

### Adding or migrating an API route

New routes go in FastAPI, in `tamandua/app/api/<context>.py`: parameters and response as Pydantic models, security
with `guard(Policy(public=…, admin=…, action=…))` (CSRF, session, second factor, role; see `app/api/security.py`) and
the logic in the business module, never in the route. Request bodies are read after the guard with `deps.body(Model,
invalid_message)`, so an unauthenticated request never reaches validation.

Then `make openapi` regenerates the schema and the panel's TypeScript types (`web/src/shared/api/`), used through
`apiGet('/api/…')`: if the API and the panel disagree, `tsc` fails. CI checks that the schema is up to date.

### Changing the database schema

Tables are defined in `tamandua/modules/<context>/tables.py`. Every change comes with its Alembic migration:

```bash
TAMANDUA_DATABASE_URL=… .venv/bin/python -c "from alembic import command; from tamandua.app.database import config; command.revision(config(), message='what changes', autogenerate=True)"
```

Review the generated file in `tamandua/app/alembic/versions/`. `tests/test_database.py` fails if the tables in the code
and the migrations don't match.

### Changing the format of existing data

Whoever upgrades Tamandua already has data: a new version must never break it or ask them to do anything by hand.

1. **Tolerant reader.** The code also reads the previous format (in a JSONB document or a `record` column):
   `dict.get` with a default for new fields, no assumptions about types that didn't exist before.
2. **A migration when data must be rewritten.** Table changes go in Alembic (above). Rewriting content goes at the end
   of `MIGRATIONS` in `tamandua/app/data_migrations.py`: idempotent, fast on large installs, and never reorder or
   delete a published one (its version is its position).
3. **A test with old data** in `tests/test_migrations.py` (or next to the module).

If the change only adds a field that may be missing, step 1 is enough: no migration needed.

`npm run build` refreshes the assets Python serves. For reload during development use `npm run dev`; Vite forwards `/api` to the backend on 8766.

## Text and languages

Tamandua speaks English and Spanish. **Code, identifiers and comments are in English**; everything a person reads
(panel, API errors, findings, fix guides, progress, reports, PR comments, notifications) exists in both languages.
Before adding or changing any of it, read [`.claude/skills/tamandua-i18n/SKILL.md`](../.claude/skills/tamandua-i18n/SKILL.md):

- **Catalogs, not literals.** Panel: `web/src/shared/i18n/locales/{en,es}/<namespace>.json` with `t('…')`. Server:
  `tamandua/shared/i18n/locales/{en,es}/<namespace>.json`.
- **Store codes, not sentences.** On the server, `msg("namespace.key", **params)` builds a language-neutral message
  that is rendered when read, in the reader's language (`localize`, `text`); `t()` only for output that isn't stored.
- **Interpret, don't translate.** English is the source and the fallback; the Spanish says the same thing the way a
  Spanish-speaking security engineer would say it, never word for word. The skill has the voice and the glossary.
- **Tests.** `tests/test_i18n.py` (part of `make test`) checks en/es parity of keys and `{{params}}` and that every
  literal key used in code exists. Tests run with `TAMANDUA_DEFAULT_LOCALE=es`; assert English explicitly with
  `Accept-Language: en`.

Documentation follows the same rule: English in `docs/`, Spanish in `docs/es/`, each page linking to the other.
