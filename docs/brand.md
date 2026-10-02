English · [Español](es/marca.md)

# Brand

## Name

**Tamandua** is the southern tamandua (*Tamandua tetradactyla*), a small anteater that lives in Colombia and across much of South America. It eats ants and termites — *bugs* — digging them out of places nobody looks with a long, precise tongue, and it wears a natural black "vest" that looks like armor. It's small, patient and very effective: exactly what we want to be for small teams.

The brand is written **Tamandua**, with no accent; in Spanish prose you can say «el tamandúa». The technical name is also `tamandua`: package, CLI, `TAMANDUA_*` variables, images, container and the GitHub commit status. The GitHub repository is `Tamandua-AppSec`; it used to be `appsec-agent`, and the old address redirects to it.

## Mascot and logo

<img src="assets/tamandua.svg" width="96" alt="Tamandua logo">

The tamandua, in profile, catches a yellow bug with its tongue on a rounded violet square. The source file is [`assets/tamandua.svg`](assets/tamandua.svg) (the same one the panel uses as its favicon); in the panel it is drawn by `web/src/shared/ui/brand-mark.tsx`.

- Minimum size: 16 px (favicon). Below 24 px the bug stops being legible, but the silhouette is still recognizable.
- Don't stretch it, rotate it or change its colors; on violet backgrounds, place the logo on white or black.
- Next to the name: the logo on the left and "Tamandua" in semibold, with a gap equal to a quarter of the logo's side.

## Color

We chose violet because security products barely use it (blues and grays dominate), it looks modern and, above all, it **doesn't compete with the severity colors**: red, orange and amber are reserved for critical, high and medium, and green for what's been fixed.

| Token | Light | Dark | Use |
| --- | --- | --- | --- |
| `--brand` | `oklch(0.52 0.21 293)` · `#7342D3` | `oklch(0.78 0.14 293)` · `#BBA5FF` | accents, links, selection, indicators |
| Logo gradient | `#8B5CF6` → `#5B21B6` | same | logo only |
| Mascot cream | `#FFF3DE` | same | logo only |
| Vest | `#1E1433` | same | logo only |
| Bug | `#FCD34D` | same | logo only |

Accent contrast: 6.1:1 on white and 8.5:1 on the dark theme's cards (WCAG AA for text). The accent never colors severity text or chart series: those have their own validated palette.

## Voice

Direct, without fear or alarmism: we say what's happening, why it matters and how to fix it. In English: plain, second person, active voice. In Spanish: neutral Latin American Spanish, *tú*. Each language is written for its own readers, not translated from the other (see [`.claude/skills/tamandua-i18n/SKILL.md`](../.claude/skills/tamandua-i18n/SKILL.md)). Tagline: **"Eats your bugs"** (in Spanish, **«Se come tus bugs»**).
