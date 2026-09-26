# Tamandua skills for coding agents

Skills in the open [Agent Skills](https://agentskills.io) format for Claude Code, Cursor, Codex and other
coding agents: they teach the agent to use Tamandua inside your repository.

| Skill | What it does |
| --- | --- |
| [`fix-findings-with-tamandua`](fix-findings-with-tamandua/SKILL.md) | Scan what your change introduces, fix the root cause of each finding and re-scan to prove it. |
| [`set-up-tamandua-in-ci`](set-up-tamandua-in-ci/SKILL.md) | Add Tamandua to CI (GitHub Actions, GitLab CI) or as a `pre-push` hook. |

They need Docker and a copy of Tamandua (in `~/tamandua` by default; set `TAMANDUA_DIR` for another folder).

## Install

```bash
npx skills add BrayansStivens/appsec-agent
```

Or by hand: copy the skill's folder into your agent's skills folder (in Claude Code, `~/.claude/skills/` or the
project's `.claude/skills/`).

The skills contain no executable code, only instructions. `tests/test_skills.py` checks their format and that they
don't mention CLI options that don't exist.
