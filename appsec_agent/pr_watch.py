"""Qué repositorios vigilan sus PRs, qué commits ya se revisaron y el vigilante que sondea.

La configuración se guarda por identidad estable (`github#<id>`): renombrar un
repositorio no apaga su vigilancia.

Sin webhooks (el MVP local no tiene URL pública) se sondea: cada
``APPSEC_AGENT_PR_POLL_SECONDS`` (300 por defecto, mínimo 60) se listan los PRs
abiertos de los repositorios activados y se encola una revisión por cada commit
de cabeza que aún no se haya revisado. Los borradores se saltan.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from . import logging_setup
from .pr_review import GATES

_log = logging_setup.get("pr_watch")
_lock = threading.Lock()
DEFAULTS = {"enabled": False, "post_comment": True, "gate": "high"}


def _path(data_dir: Path) -> Path:
    return data_dir / "pr-watch.json"


def load(data_dir: Path) -> dict:
    try:
        payload = json.loads(_path(data_dir).read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError, OSError):
        return {"repositories": {}, "reviewed": {}}
    if not isinstance(payload, dict):
        return {"repositories": {}, "reviewed": {}}
    payload.setdefault("repositories", {})
    payload.setdefault("reviewed", {})
    return payload


def _save(data_dir: Path, payload: dict) -> None:
    target = _path(data_dir)
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, target)


def settings(data_dir: Path, source_id: str) -> dict:
    return {**DEFAULTS, **load(data_dir)["repositories"].get(source_id, {})}


def configure(data_dir: Path, source_id: str, *, enabled=None, post_comment=None, gate=None, by: str) -> dict:
    if gate is not None and gate not in GATES:
        raise ValueError("Umbral inválido")
    with _lock:
        payload = load(data_dir)
        current = {**DEFAULTS, **payload["repositories"].get(source_id, {})}
        for key, value in (("enabled", enabled), ("post_comment", post_comment), ("gate", gate)):
            if value is not None:
                current[key] = value
        current.update(updated_by=by, updated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        payload["repositories"][source_id] = current
        _save(data_dir, payload)
    _log.info("pr_watch_configured", extra={"user": by, "reason": f"{source_id}: {current['enabled']}"})
    return current


def forget(data_dir: Path, key: str) -> None:
    with _lock:
        payload = load(data_dir)
        changed = payload["repositories"].pop(key, None) is not None
        changed = payload["reviewed"].pop(key, None) is not None or changed
        if changed:
            _save(data_dir, payload)


def migrate(data_dir: Path, repositories: list[dict]) -> None:
    """Configuración antigua guardada por nombre (`github:owner/repo`) → identidad estable."""
    by_name = {item["id"]: item["uid"] for item in repositories if item.get("uid")}
    with _lock:
        payload = load(data_dir)
        changed = False
        for section in ("repositories", "reviewed"):
            for key in [key for key in payload[section] if key in by_name]:
                payload[section].setdefault(by_name[key], payload[section][key])
                del payload[section][key]
                changed = True
        if changed:
            _save(data_dir, payload)


def reviewed(data_dir: Path, source_id: str) -> dict:
    return load(data_dir)["reviewed"].get(source_id, {})


def mark(data_dir: Path, source_id: str, number: int, head_sha: str, run_id: str) -> None:
    with _lock:
        payload = load(data_dir)
        payload["reviewed"].setdefault(source_id, {})[str(number)] = {"head_sha": head_sha, "run_id": run_id}
        _save(data_dir, payload)


def interval() -> int:
    return max(60, int(os.environ.get("APPSEC_AGENT_PR_POLL_SECONDS", "300") or 300))


def mark_closed(data_dir: Path, key: str, number: int) -> None:
    with _lock:
        payload = load(data_dir)
        entry = payload["reviewed"].get(key, {}).get(str(number))
        if entry is not None:
            entry["closed"] = True
            _save(data_dir, payload)


class Watcher:
    """Hilo que sondea los PRs de los repositorios activados. Solo lo arranca `serve`."""

    def __init__(self, data_dir: Path, jobs, installation_for):
        self.data_dir, self.jobs, self.installation_for = data_dir, jobs, installation_for
        self.interval = interval()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="appsec-pr-watch", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        _log.info("pr_watch_started", extra={"reason": f"cada {self.interval} s"})
        # La primera vuelta no espera el intervalo completo: tras reiniciar, los PRs abiertos se revisan enseguida.
        delay = min(15, self.interval)
        while not self._stop.wait(delay):
            delay = self.interval
            try:
                self.poll()
            except Exception:  # noqa: BLE001 — un fallo de red no debe matar al vigilante
                _log.exception("pr_watch_failed")

    def _closed(self, installation: int, key: str, repository: str, done: dict, open_numbers: set[int]) -> None:
        """PRs revisados que ya no están abiertos: sin merge retiran sus hallazgos; con merge esperan al escaneo."""
        from .findings_registry import pull_closed
        from .github_app import GitHubAppError, pull_request
        for number, entry in done.items():
            if entry.get("closed") or int(number) in open_numbers:
                continue
            try:
                pull = pull_request(installation, repository, int(number))
            except GitHubAppError:
                continue
            if pull.get("state") != "closed":
                continue
            pull_closed(self.data_dir, key, int(number), merged=pull["merged"], when=pull.get("closed_at") or "")
            mark_closed(self.data_dir, key, int(number))
            _log.info("pr_closed", extra={"reason": f"{repository}#{number} {'mergeado' if pull['merged'] else 'cerrado sin merge'}"})

    def poll(self) -> int:
        from .assets import reconcile
        from .github_app import GitHubAppError, installation_repositories, open_pull_requests
        configured = self.installation_for()
        installations = [configured] if isinstance(configured, int) else configured or []
        if not installations:
            return 0
        repositories = []
        failed = False
        for installation in installations:
            try:
                repositories.extend({**item, "installation_id": installation}
                                    for item in installation_repositories(installation, fresh=True))
            except GitHubAppError as exc:
                _log.warning("pr_repos_failed", extra={"reason": f"{installation}: {exc}"})
                failed = True
        if failed:
            # Una respuesta parcial no demuestra que los repositorios de otra cuenta desaparecieron.
            return 0
        migrate(self.data_dir, repositories)
        # Solo las cuentas aún conectadas pueden demostrar la ausencia de un repositorio.
        from .integrations import github_connections
        accounts = {row["account"].casefold() for row in github_connections(self.data_dir)
                    if isinstance(row.get("account"), str)}
        reconcile(self.data_dir, repositories, active_accounts=accounts or None)
        by_uid = {item["uid"]: item for item in repositories}
        queued = 0
        for key, config in load(self.data_dir)["repositories"].items():
            if not config.get("enabled") or key not in by_uid:
                continue
            source_id, repository = by_uid[key]["id"], by_uid[key]["name"]
            installation = by_uid[key]["installation_id"]
            try:
                pulls = open_pull_requests(installation, repository)
            except GitHubAppError as exc:
                _log.warning("pr_list_failed", extra={"reason": f"{repository}: {exc}"})
                continue
            done = reviewed(self.data_dir, key)
            self._closed(installation, key, repository, done, {pull["number"] for pull in pulls})
            for pull in pulls:
                if pull["draft"] or not pull["head_sha"] or done.get(str(pull["number"]), {}).get("head_sha") == pull["head_sha"]:
                    continue
                if self.jobs.pending() >= 20:
                    return queued
                self.jobs.enqueue_pr_review(source_id=source_id, uid=key, pull=pull, installation_id=installation, requested_by="vigilante")
                queued += 1
        watched = sum(1 for config in load(self.data_dir)["repositories"].values() if config.get("enabled"))
        _log.info("pr_watch_poll", extra={"reason": f"{watched} repositorios vigilados, {queued} revisiones encoladas"})
        return queued
