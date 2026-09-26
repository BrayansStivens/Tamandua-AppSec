---
name: tamandua-i18n
description: How Tamandua speaks English and Spanish — catalogs, language-neutral stored messages, and the "interpret, don't translate" writing rules. Use ALWAYS when adding or changing any user-facing text (panel, API errors, findings, fix guides, progress messages, reports, PR comments, notifications, rule texts) and when reviewing a diff that touches them.
---

# Tamandua i18n

Every word a person reads exists in **English (source) and Spanish**, written for each audience. Nothing
user-facing is hard-coded, and nothing we store is frozen in one language.

## Principles

1. **Interpret, don't translate.** Write what a security engineer in that language would naturally say. Same
   meaning, same precision, idiomatic phrasing. Never word-for-word, never machine-literal.
2. **English is the source and the fallback.** Add the English text first, then the Spanish interpretation. Both
   are required for product text; tests fail if one is missing or their `{{params}}` differ.
3. **Store codes, not sentences.** Anything persisted (findings, progress, limitations, errors) holds a message
   code plus parameters, rendered when read, in the reader's language.
4. **Third-party text stays as published.** Advisory summaries (NVD, OSV, GHSA), scanner check names (Checkov,
   Gitleaks, zizmor) and CVE descriptions are shown verbatim. Never machine-translate them; wrap them as parameters
   of our own sentence.
5. **User content is one language.** Custom rules, reasons, descriptions: stored as written, shown as written.
   A second language is optional, never required.
6. **Never assemble sentences from fragments.** Word order differs between languages; use one key with
   `{{params}}`. Plurals use `count` (`key_one` / `key_other`).
7. **Keep names as names.** Tamandua, GitHub, GitLab, Jira, Slack, CVE, CWE, GHSA, KEV, EPSS, CVSS, SBOM, VEX,
   SARIF, OWASP, CRA, SOC 2, ISO 27001, TOTP, SAST, SCA, IaC, PR — untranslated.

## Voice

- **English:** plain, direct, second person, active voice. "Update lodash to 4.17.21", not "It is recommended
  that lodash be updated".
- **Spanish:** neutral Latin American Spanish, *tú*, no voseo, no regionalisms. Same brevity as the English.
- Conclusions first, then detail. Sentence case for labels and buttons. No exclamation marks.

## Glossary

| English | Spanish | Note |
| --- | --- | --- |
| finding | hallazgo | never "vulnerabilidad" unless it is a confirmed CVE |
| scan / analysis | análisis | "escaneo" only in technical copy |
| fix (verb) / remediate | corregir | "remediado" as a finding state |
| fixed (state) | remediado | |
| excluded | excluido | |
| accepted risk | riesgo aceptado | |
| false positive | falso positivo | |
| triage | triage | |
| exposed secret | secreto expuesto | |
| dependency | dependencia | |
| lockfile | lockfile | |
| repository | repositorio | |
| pull request | pull request | "PR" in tight spaces |
| severity: critical/high/medium/low | crítica/alta/media/baja | |
| priority: act now / attend / track | actuar ya / atender / seguir | |
| due date (SLA) | plazo de corrección | |
| two-factor authentication | segundo factor | |
| sign in / sign out | iniciar sesión / cerrar sesión | |
| Tamandua rules | reglas de Tamandua | built-in SAST rules (not "custom") |
| custom rules | reglas personalizadas | only rules written by the user |

## Panel (React)

- Catalogs: `web/src/shared/i18n/locales/{en,es}/<namespace>.json`, nested keys in `lower_snake_case`. One
  namespace per feature or page (`findings`, `dashboard`, `auth`…); shared words live in `common`.
- `const { t } = useTranslation('findings')` then `t('filters.severity')`; other namespaces with
  `t('common:save')`. Markup inside a sentence: `<Trans>`. Every visible string counts: labels, buttons,
  placeholders, `aria-label`, `title`, empty states, toasts, `alert()`.
- Dates and numbers: `formatDate`, `formatDay`, `formatNumber`, `formatPercent` from `@/shared/i18n/format`.
  Never `toLocaleString('es-CO')`.
- Text that comes from the API is already localized: render it, don't translate it.
- Keys must be literal strings (`t('a.b')`) so the tests can find them. Map dynamic values through an object of
  literal keys: `const LABEL = { open: 'status.open' } as const` → `t(LABEL[status])`.

## Server (Python)

- Catalogs: `tamandua/shared/i18n/locales/{en,es}/<namespace>.json`, same format; keys are `namespace.path`.
- `from tamandua.shared.i18n import msg, inline, localize, text, t`
  - `msg("findings.sca.upgrade", package=name, version=target)` — a message to store or return. Parameters may
    be raw strings (third-party text) or other messages.
  - `inline({"en": ..., "es": ...})` — text that carries its own languages (rule texts, user content).
  - `localize(value, locale)` renders every message inside any structure; `text(value, locale)` gives a string.
  - `t(key, locale, **params)` renders one key immediately (only when the output is not stored).
- The API renders for the request: table routes through `Request.json()`, typed routes with `context.render()`,
  errors through `ApiError(status, msg(...))`. Reports, PR comments, notifications, Jira and the CLI render with an
  explicit locale (`TAMANDUA_DEFAULT_LOCALE`, default `en`, when nobody asked).
- Code that inspects stored text (sorting, truncating, searching, dedup) must work on codes and parameters, or
  call `text(value, locale)` first. Never slice a message dict.
- Tamandua rules (`rules/*.yml`): keep `message` in English (Opengrep requires it) and put both languages in
  `metadata.title` and `metadata.fix` as `{en: ..., es: ...}`. The engine stores them with `inline()`.

## Checks

- `make test` runs `tests/test_i18n.py`: en/es parity (keys and params) on both sides, and every literal key
  used in code exists.
- `cd web && npx tsc -b && npx oxlint src`.
- Tests run with `TAMANDUA_DEFAULT_LOCALE=es`; assert English explicitly with `Accept-Language: en`.
