---
name: tamandua-design
description: Reglas de diseño de Tamandua para la interfaz (web/src), los informes PDF/Markdown y el diagrama de amenazas. Úsala SIEMPRE antes de crear o cambiar una vista, un componente, un informe, una exportación o el diagrama, y para revisar un diff que toque cualquiera de ellos.
---

# Diseño de Tamandua

Tres superficies, las mismas ideas: **primero la conclusión, después el detalle; agrupar por acción; solo tokens; accesible (WCAG 2.2 AA); nada de texto sin escapar.**
Si una regla choca con lo que pide el usuario, pregunta; no la rompas en silencio.

## 1. Interfaz (web/src)

- **Color: solo tokens** de `web/src/index.css` (`text-danger`, `bg-warning-soft`, `border-info-line`, `bg-brand/10`, `text-app-muted`…). Nunca paleta suelta de Tailwind (`bg-red-500`) ni hexadecimal. `tests/test_ui_tokens.py` lo hace cumplir.
  - Semánticos: `danger`, `attention`, `warning`, `info`, `success` con `-soft` (fondo) y `-line` (borde); `danger-solid` + `on-solid` para lo sólido; `brand`; neutros `app-*`, `panel`, `inset`.
  - `app-faint` solo para bordes y adornos, nunca texto.
- **Contraste**: texto ≥ 4,5:1, bordes que identifican algo ≥ 3:1. Si añades un token, compruébalo en claro y en oscuro.
- **Foco visible** en todo control (ya global: `:focus-visible` con `--brand`). No lo quites con `outline-none` sin alternativa.
- **Movimiento**: animaciones con `motion-safe:`; `prefers-reduced-motion` las apaga.
- **Tamaños**: texto ≥ 11 px; objetivos de clic ≥ 24 px (`min-h-6`, `size-6`).
- **Semántica y ARIA en español**: `aria-pressed` (conmutadores), `aria-expanded`, `aria-current`, `role="radiogroup"`/`radio` con `aria-checked`, `role="status"`/`alert`/`progressbar`; cada input con su `<label htmlFor>`; `CardTitle` es un encabezado real.
- **Carga**: esqueletos con la forma del contenido (`Bone`, `SkeletonList`, `SkeletonTable`, `SkeletonTiles`, `SkeletonCard` de `components/loading.tsx`), anunciados una vez ("Cargando …"). Nunca un estado vacío falso mientras carga.
- **Ley de Hick**: una acción principal y el resto en un menú (`components/ui/menu.tsx`); navegación agrupada; lo avanzado tras «Más opciones»/«Más filtros». Formularios con valores por defecto: se puede generar sin tocar nada.
- **Listas largas**: paginación o búsqueda en el servidor; nunca cargar todo.

## 2. Informes (PDF y Markdown)

Todo PDF se construye con `tamandua/modules/reporting/design.py` (tokens, `header`, `meta`, `kpis`, `chip`, `table`, `h2`, `build`, `wide_page`). No crees estilos ni colores propios.

**Estructura, en este orden:**
1. Cabecera: antetítulo (qué tipo de informe), título (el sistema), subtítulo (periodo o descripción) y `meta` (quién, qué, cuándo, referencia).
2. **Cifras clave** (`kpis`, como mucho 6) y una frase de resumen con los números.
3. **Qué hacer primero**: tabla corta (≤ 15 filas) con severidad, qué, dónde y la acción en una frase.
4. El cuerpo agrupado **por acción**, no por aviso:
   - dependencias: una fila por paquete (manifiesto + versión) con la versión que cierra todos sus avisos → `remediation.fix_groups` y `remediation.action`;
   - amenazas de reglas: una fila por patrón con los componentes afectados (`threat_report.digest`);
   - código: detalle solo de críticos y altos; medios y bajos en tabla.
5. Método y **cobertura: lo que no se analizó se dice** ("no equivale a «sin hallazgos»"). Nunca presentes un análisis incompleto como limpio.
6. Anexos compactos (una fila por elemento, sin descripciones largas) y con tope; lo íntegro queda en JSON/SARIF/panel.
7. Aviso final: evidencia técnica, revisión humana, no es certificación. Firmas solo en los de auditoría.

**Reglas de forma:**
- Severidad siempre con `chip` (colores fijos). KEV marcado en rojo junto al hallazgo.
- Celdas cortas: acción con `action(entry, short=True)`; listas con `listing(items, n)` («a, b y 4 más»).
- Todo texto que venga de un repositorio, modelo o formulario pasa por `t()` (escapa y acota). En Markdown, `|` escapado en celdas.
- Títulos de sección con `h2()` (el salto condicional evita huérfanos). Nada de `keepWithNext` en tablas grandes.
- Tono: español, concreto, sin exagerar (no «explotable» sin prueba; un indicio es una señal, no una confirmación).
- Presupuesto orientativo: técnico de un repositorio ≤ 15 páginas sin anexo; modelo de amenazas ≤ 15. Si te pasas, agrupa más o mueve a anexo.
- **Excepción: evidencia para auditoría** (SOC 2, ISO, consolidado). El lector es un auditor: alcance, controles y método van antes de los
  hallazgos, sin «Qué hacer primero»; la tabla de hallazgos agrupada es la evidencia y va completa; el detalle lleva tope (`DETAIL_LIMIT`).
- Cobertura: usa `coverage_gaps(steps)` (parcial, no ejecutado, no concluyente, falló). «Todos los motores se completaron» solo si todos
  están en `completed`. En amenazas, di si se buscaron indicios (componentes con repositorio enlazado).

## 3. Diagrama de amenazas

- Colocación: `tamandua/modules/threats/diagram.py` y `web/src/components/threat-layout.ts` son **el mismo algoritmo**; si cambias uno, cambia el otro. `tests/test_threat_layout_parity.py` lo comprueba.
- Columnas por recorrido de los datos (distancia a los actores), bloques por frontera sin solapes, reordenados por vecinos, rejilla de 8 px, pilas ≤ 5.
- Colores: paleta de tokens (`COLORS` en Python, `threat-colors.ts` en el panel): `neutral, brand, info, success, warning, attention, danger`. Sin elegir, el del papel del componente; siempre con leyenda. Nunca hexadecimal libre del usuario.
- Formas: proceso redondeado, almacén entre dos líneas, tercero discontinuo. Flujo sin cifrar: rojo discontinuo.
- Etiquetas cortas: «n.º · PROTOCOLO». Lo que viaja, en la tabla de flujos del informe con el mismo número.
- El SVG y el PDF salen de la misma `scene()`: no dibujes en uno lo que no esté en el otro.

## Cómo verificar antes de dar algo por terminado

1. `make test` (incluye `test_ui_tokens`, `test_report_design`, `test_threat_layout_parity`) y `cd web && npx tsc -b && npx oxlint src`.
2. **Míralo**: genera el PDF con datos reales (`data/runs/*/run.json`) y conviértelo con `pdftoppm -r 60 -png`; el SVG con `rsvg-convert`; la UI con una página de vista previa temporal (bórrala después). Revisa páginas, huecos, textos cortados y contraste.
3. Compara páginas antes/después cuando cambies un informe.

Para revisar un diff contra estas reglas, usa el agente `design-reviewer`.
