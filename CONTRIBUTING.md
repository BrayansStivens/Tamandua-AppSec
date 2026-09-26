English · [Español](CONTRIBUTING.es.md)

# Contributing

Thanks for your interest. Before you open a PR:

1. Open an issue first to discuss big changes.
2. Run the tests and the linters:

   ```bash
   make dev-setup   # once
   make check       # backend tests and architecture contracts + panel types and lint
   ```

   CI ([`ci.yml`](.github/workflows/ci.yml)) repeats this on every PR, checks that `tamandua/app/static` has been
   rebuilt (`make web`) and scans the PR with Tamandua itself: it blocks anything the PR introduces at high severity or above.

3. Follow the house rules:
   - **No new backend dependencies** unless they are essential: today they are the ones in `requirements.txt` (FastAPI, uvicorn, Pydantic, SQLAlchemy, Alembic, psycopg, `cryptography` and ReportLab), at pinned versions.
   - **No secrets in logs, responses or files under `data/`.** Secrets go through `vault.py`.
   - Every new route is declared with its permission, its action header (POST) and its maximum body size; the route table test checks it.
   - Whatever couldn't be tested is said so (`not_tested` with a reason); it is never presented as "no vulnerabilities".
   - Code, identifiers and comments in English. Every text a person reads (panel, errors, findings, reports) exists in English and Spanish through the catalogs: interpret, don't translate ([`.claude/skills/tamandua-i18n/SKILL.md`](.claude/skills/tamandua-i18n/SKILL.md)). Documentation lives in `docs/` (English) and `docs/es/` (Spanish).
   - If you change the format of something already stored in `data/`: a tolerant reader and, if data has to be rewritten, a migration with its test (see [development.md](docs/development.md)).
4. Never paste tokens, keys or unreviewed logs into issues or PRs.

**Signing the CLA.** On your first PR, a bot will ask you to accept the [Contributor License Agreement](CLA.md) with a comment. You keep your copyright; the agreement lets us distribute your contribution under the [AGPL-3.0](LICENSE) (the rules in `rules/` under MIT) and also in a possible commercial edition, with the commitment that it stays available in the free edition.

Details for running without containers are in [docs/development.md](docs/development.md).
