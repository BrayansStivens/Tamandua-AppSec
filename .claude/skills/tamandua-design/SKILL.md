---
name: tamandua-design
description: Tamandua's design rules for the panel (web/src), the PDF/Markdown reports and the threat diagram. Use ALWAYS before creating or changing a view, a component, a report, an export or the diagram, and when reviewing a diff that touches any of them.
---

# Tamandua design

Three surfaces, one set of ideas: **conclusion first, detail after; group by action; tokens only; accessible (WCAG 2.2 AA); no unescaped text.**
If a rule conflicts with what the user asks for, ask; never break it silently.

## 1. Panel (web/src)

- **Color: tokens only** from `web/src/index.css` (`text-danger`, `bg-warning-soft`, `border-info-line`, `bg-brand/10`, `text-app-muted`…). Never raw Tailwind palette classes (`bg-red-500`) or hex values. `tests/test_ui_tokens.py` enforces it.
  - Semantic: `danger`, `attention`, `warning`, `info`, `success`, each with `-soft` (background) and `-line` (border); `danger-solid` + `on-solid` for solid fills; `brand`; neutrals `app-*`, `panel`, `inset`.
  - `app-faint` is for borders and decoration only, never text.
- **Contrast**: text ≥ 4.5:1, borders that identify something ≥ 3:1. If you add a token, check it in both light and dark mode.
- **Visible focus** on every control (already global: `:focus-visible` with `--brand`). Never remove it with `outline-none` without an alternative.
- **Motion**: animations behind `motion-safe:`; `prefers-reduced-motion` turns them off.
- **Sizes**: text ≥ 11 px; click targets ≥ 24 px (`min-h-6`, `size-6`).
- **Semantics and ARIA**: `aria-pressed` (toggles), `aria-expanded`, `aria-current`, `role="radiogroup"`/`radio` with `aria-checked`, `role="status"`/`alert`/`progressbar`; every input has its `<label htmlFor>`; `CardTitle` is a real heading. ARIA labels are user-facing text: they come from the i18n catalogs (`.claude/skills/tamandua-i18n/SKILL.md`), in English and Spanish.
- **Loading**: skeletons shaped like the content (`Bone`, `SkeletonList`, `SkeletonTable`, `SkeletonTiles`, `SkeletonCard` from `shared/ui/loading.tsx`), announced once ("Loading…"). Never show a fake empty state while loading.
- **Hick's law**: one primary action, the rest in a menu (`shared/ui/menu.tsx`); grouped navigation; advanced options behind "More options"/"More filters". Forms have defaults: the user can generate without touching anything.
- **Long lists**: server-side pagination or search; never load everything.

## 2. Reports (PDF and Markdown)

Every PDF is built with `tamandua/modules/reporting/design.py` (tokens, `header`, `meta`, `kpis`, `chip`, `table`, `h2`, `build`, `wide_page`). Do not create your own styles or colors.

**Structure, in this order:**
1. Header: kicker (which kind of report), title (the system), subtitle (period or description) and `meta` (who, what, when, reference).
2. **Key figures** (`kpis`, at most 6) and one summary sentence with the numbers.
3. **What to do first**: a short table (≤ 15 rows) with severity, what, where and the action in one sentence.
4. The body grouped **by action**, not by advisory:
   - dependencies: one row per package (manifest + version) with the version that closes all its advisories → `remediation.fix_groups` and `remediation.action`;
   - rule-based threats: one row per pattern with the affected components (`threat_report.digest`);
   - code: full detail only for critical and high; medium and low in a table.
5. Method and **coverage: say what was not analyzed** ("this is not the same as 'no findings'"). Never present an incomplete analysis as clean.
6. Compact appendices (one row per item, no long descriptions), with a cap; the full data stays in JSON/SARIF/the panel.
7. Closing notice: technical evidence, human review required, not a certification. Signatures only on audit reports.

**Form rules:**
- Severity always with `chip` (fixed colors). KEV flagged in red next to the finding.
- Short cells: action with `action(entry, short=True)`; lists with `listing(items, n)` ("a, b and 4 more").
- All text coming from a repository, a model or a form goes through `t()` (escapes and truncates). In Markdown, escape `|` inside cells.
- Section titles with `h2()` (its conditional page break avoids orphans). No `keepWithNext` on large tables.
- Tone: concrete, no overstatement (never "exploitable" without proof; an indicator is a signal, not a confirmation). Wording in the reader's language through the i18n catalogs, English and Spanish.
- Rough budget: a single-repository technical report ≤ 15 pages without appendix; a threat model ≤ 15. If you exceed it, group more or move content to an appendix.
- **Exception: audit evidence** (SOC 2, ISO, consolidated). The reader is an auditor: scope, controls and method come before the
  findings, with no "What to do first"; the grouped findings table is the evidence and is complete; detail is capped (`DETAIL_LIMIT`).
- Coverage: use `coverage_gaps(steps)` (partial, not run, inconclusive, failed). Say "all engines completed" only if every step
  is `completed`. For threats, say whether indicators were searched (components with a linked repository).

## 3. Threat diagram

- Placement: `tamandua/modules/threats/diagram.py` and `web/src/features/threats/threat-layout.ts` are **the same algorithm**; if you change one, change the other. `tests/test_threat_layout_parity.py` checks it.
- Columns follow the data path (distance from the actors), one block per boundary without overlaps, reordered by neighbors, 8 px grid, stacks ≤ 5.
- Colors: the token palette (`COLORS` in Python, `threat-colors.ts` in the panel): `neutral, brand, info, success, warning, attention, danger`. If none is chosen, use the component role's color; always with a legend. Never free-form hex from the user.
- Shapes: process rounded, data store between two lines, third party dashed. Unencrypted flow: dashed red.
- Short labels: "n · PROTOCOL" (e.g. `3 · HTTPS`). What travels goes in the report's flow table under the same number.
- The SVG and the PDF come from the same `scene()`: never draw in one what is not in the other.

## How to verify before calling it done

1. `make test` (includes `test_ui_tokens`, `test_report_design`, `test_threat_layout_parity`) and `cd web && npx tsc -b && npx oxlint src`.
2. **Look at it**: generate the PDF with real data (`data/runs/*/run.json`) and convert it with `pdftoppm -r 60 -png`; the SVG with `rsvg-convert`; the panel with a temporary preview page (delete it afterwards). Check pages, gaps, clipped text and contrast.
3. Compare pages before/after whenever you change a report.

To review a diff against these rules, use the `design-reviewer` agent.
