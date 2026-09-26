# Skills de Tamandua para asistentes de programación

Skills en el formato abierto [Agent Skills](https://agentskills.io) para Claude Code, Cursor, Codex y otros
asistentes: enseñan al asistente a usar Tamandua dentro de tu repositorio.

| Skill | Para qué |
| --- | --- |
| [`fix-findings-with-tamandua`](fix-findings-with-tamandua/SKILL.md) | Analizar lo que introduce tu cambio, corregir la causa de cada hallazgo y volver a analizar para demostrarlo. |
| [`set-up-tamandua-in-ci`](set-up-tamandua-in-ci/SKILL.md) | Añadir Tamandua al CI (GitHub Actions, GitLab CI) o como hook `pre-push`. |

Necesitan Docker y una copia de Tamandua (por defecto en `~/tamandua`; otra carpeta con `TAMANDUA_DIR`).

## Instalar

```bash
npx skills add BrayansStivens/appsec-agent
```

O a mano: copia la carpeta de la skill en la de tu asistente (en Claude Code, `~/.claude/skills/` o
`.claude/skills/` del proyecto).

Las skills no llevan código ejecutable: solo instrucciones. `tests/test_skills.py` comprueba su formato y que no
citan opciones de la CLI que no existan.
