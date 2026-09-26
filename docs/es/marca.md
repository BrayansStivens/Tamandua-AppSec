[English](../brand.md) · Español

# Marca

## Nombre

**Tamandua** es el oso hormiguero de collar (*Tamandua tetradactyla*), que vive en Colombia y en buena parte de Sudamérica. Se alimenta de hormigas y termitas —de *bugs*— que saca de donde nadie mira con una lengua larga y precisa, y lleva un «chaleco» negro natural que parece una armadura. Es pequeño, paciente y muy eficaz: justo lo que queremos ser para equipos pequeños.

Se escribe **Tamandua**, sin tilde, en la marca; en texto en español se puede decir «el tamandúa». El nombre técnico también es `tamandua`: paquete, CLI, variables `TAMANDUA_*`, imágenes, contenedor y estado de commit en GitHub. Solo el repositorio de GitHub conserva el nombre anterior, `appsec-agent`.

## Mascota y logo

<img src="../assets/tamandua.svg" width="96" alt="Logo de Tamandua">

El tamandúa, de perfil, atrapa un bug amarillo con la lengua sobre un cuadrado violeta redondeado. El archivo fuente es [`assets/tamandua.svg`](../assets/tamandua.svg) (el mismo que usa el panel como favicon); en el panel lo dibuja `web/src/shared/ui/brand-mark.tsx`.

- Tamaño mínimo: 16 px (favicon). Por debajo de 24 px el bug deja de leerse, pero la silueta se reconoce.
- No se deforma, no se gira y no se cambian sus colores; sobre fondos violetas usa el logo sobre blanco o negro.
- Junto al nombre: el logo a la izquierda y «Tamandua» en semibold, con un espacio igual a un cuarto del lado del logo.

## Color

El violeta se eligió porque apenas se usa en seguridad (dominan los azules y grises), se ve moderno y, sobre todo, **no compite con los colores de severidad**: rojo, naranja y ámbar quedan reservados para crítica, alta y media, y el verde para lo corregido.

| Token | Claro | Oscuro | Uso |
| --- | --- | --- | --- |
| `--brand` | `oklch(0.52 0.21 293)` · `#7342D3` | `oklch(0.78 0.14 293)` · `#BBA5FF` | acentos, enlaces, selección, indicadores |
| Degradado del logo | `#8B5CF6` → `#5B21B6` | igual | solo en el logo |
| Crema de la mascota | `#FFF3DE` | igual | solo en el logo |
| Chaleco | `#1E1433` | igual | solo en el logo |
| Bug | `#FCD34D` | igual | solo en el logo |

Contraste del acento: 6,1:1 sobre blanco y 8,5:1 sobre las tarjetas del tema oscuro (WCAG AA para texto). El acento nunca pinta texto de severidad ni series de gráficas: esas tienen su propia paleta validada.

## Voz

Directa, sin miedo ni alarmismo: decimos qué pasa, por qué importa y cómo se arregla. En español: neutro latinoamericano, de *tú*. En inglés: llano, en segunda persona y en voz activa. Cada idioma se escribe para sus lectores, no se traduce del otro (ver [`.claude/skills/tamandua-i18n/SKILL.md`](../../.claude/skills/tamandua-i18n/SKILL.md)). Lema: **«Se come tus bugs»** (en inglés, **"Eats your bugs"**).
