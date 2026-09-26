"""Qué repositorios se vigilan (sus PRs y su rama principal), qué commits ya se revisaron y el vigilante que sondea.

La configuración se guarda por identidad estable (`github#<id>`): renombrar un
repositorio no apaga su vigilancia.

Sin webhooks (el MVP local no tiene URL pública) se sondea: cada
``TAMANDUA_PR_POLL_SECONDS`` (300 por defecto, mínimo 60) se listan los PRs
abiertos de los repositorios activados y se encola una revisión por cada commit
de cabeza que aún no se haya revisado. Los borradores se saltan.

Only PRs into the repository's target branches are reviewed (`base_branches`; empty means the default branch).
Each target branch is watched too: when its latest commit changes, the repository is rescanned at that commit so
the PR baseline doesn't go stale after a merge. At most once every ``TAMANDUA_BRANCH_MIN_MINUTES`` (60 by default)
per branch, a few per round and only with an almost empty queue: manual scans and PR reviews don't wait behind it.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from tamandua.shared import documents
from tamandua.shared import events
from tamandua.shared import log as logging_setup
from tamandua.modules.pullrequests.review import GATES
from tamandua.shared.i18n import msg, text

_log = logging_setup.get("pr_watch")
DEFAULTS = {"enabled": False, "post_comment": True, "gate": "high", "branch": True, "base_branches": []}
MAX_BASE_BRANCHES = 10
BRANCH_PER_POLL = 3     # reanálisis de rama principal encolados por vuelta, como mucho
BRANCH_QUEUE_LIMIT = 2  # solo si en la cola hay menos que esto


@dataclass(frozen=True)
class RepositoriesListed:
    """The COMPLETE repository list of the connected installations was read (a partial one is never published):
    what's missing from it can be retired. `active_accounts`: the accounts still connected (None: all)."""
    data_dir: Path
    repositories: list[dict]
    active_accounts: set[str] | None


class WatchError(ValueError):
    """`message` is what people read (rendered per reader); str() stays English, for logs."""

    def __init__(self, message):
        super().__init__(text(message, "en"))
        self.message = message


def load(data_dir: Path) -> dict:
    payload = documents.load(data_dir, "pr-watch", {})
    if not isinstance(payload, dict):
        return {"repositories": {}, "reviewed": {}, "branches": {}}
    payload.setdefault("repositories", {})
    payload.setdefault("reviewed", {})
    payload.setdefault("branches", {})
    return payload


def _save(data_dir: Path, payload: dict) -> None:
    documents.save(data_dir, "pr-watch", payload)


def settings(data_dir: Path, source_id: str) -> dict:
    return {**DEFAULTS, **load(data_dir)["repositories"].get(source_id, {})}


def configure(data_dir: Path, source_id: str, *, enabled=None, post_comment=None, gate=None, branch=None, by: str) -> dict:
    return configure_many(data_dir, [source_id], enabled=enabled, post_comment=post_comment, gate=gate, branch=branch, by=by)[0]


def configure_many(data_dir: Path, keys: list[str], *, enabled=None, post_comment=None, gate=None, branch=None, by: str) -> list[dict]:
    """Varios repositorios con una sola escritura: activar cientos no reescribe el archivo cientos de veces."""
    if gate is not None and gate not in GATES:
        raise WatchError(msg("pulls.watch.invalid_gate"))
    results = []
    with documents.lock(data_dir, "pr-watch"):
        payload = load(data_dir)
        when = datetime.now(timezone.utc).isoformat(timespec="seconds")
        for key in dict.fromkeys(keys):
            current = {**DEFAULTS, **payload["repositories"].get(key, {})}
            for field, value in (("enabled", enabled), ("post_comment", post_comment), ("gate", gate), ("branch", branch)):
                if value is not None:
                    current[field] = value
            current.update(updated_by=by, updated_at=when)
            payload["repositories"][key] = current
            results.append(current)
        _save(data_dir, payload)
    reason = f"{keys[0]}: {results[0]['enabled']}" if len(results) == 1 else f"{len(results)} repositorios: {enabled}"
    _log.info("pr_watch_configured", extra={"user": by, "reason": reason})
    return results


def target_branches(config: dict, default_branch: str | None) -> list[str]:
    """Branches whose PRs are reviewed and whose baseline is kept fresh; empty if nothing is known."""
    configured = [branch for branch in config.get("base_branches") or [] if isinstance(branch, str)]
    return configured or ([default_branch] if default_branch else [])


def set_base_branches(data_dir: Path, key: str, branches: list[str], *, default_branch: str | None, by: str) -> dict:
    """Stores the (already validated) target branches and drops the watch state of branches no longer targeted."""
    with documents.lock(data_dir, "pr-watch"):
        payload = load(data_dir)
        current = {**DEFAULTS, **payload["repositories"].get(key, {})}
        current.update(base_branches=list(branches), updated_by=by,
                       updated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        payload["repositories"][key] = current
        keep = set(target_branches(current, default_branch))
        heads = {name: state for name, state in _heads(payload["branches"].get(key), default_branch).items() if name in keep}
        if heads:
            payload["branches"][key] = {"heads": heads}
        else:
            payload["branches"].pop(key, None)
        _save(data_dir, payload)
    _log.info("pr_branches_configured", extra={"user": by, "reason": f"{key}: {', '.join(branches) or 'default'}"})
    return current


def forget(data_dir: Path, key: str) -> None:
    with documents.lock(data_dir, "pr-watch"):
        payload = load(data_dir)
        changed = payload["repositories"].pop(key, None) is not None
        changed = payload["reviewed"].pop(key, None) is not None or changed
        changed = payload["branches"].pop(key, None) is not None or changed
        if changed:
            _save(data_dir, payload)


def migrate(data_dir: Path, repositories: list[dict]) -> None:
    """Configuración antigua guardada por nombre (`github:owner/repo`) → identidad estable."""
    by_name = {item["id"]: item["uid"] for item in repositories if item.get("uid")}
    with documents.lock(data_dir, "pr-watch"):
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
    with documents.lock(data_dir, "pr-watch"):
        payload = load(data_dir)
        payload["reviewed"].setdefault(source_id, {})[str(number)] = {"head_sha": head_sha, "run_id": run_id}
        _save(data_dir, payload)


def _heads(entry, default_branch: str | None = None) -> dict[str, dict]:
    """Watch state per branch. Older entries hold a single state, which was always the default branch's."""
    if not isinstance(entry, dict):
        return {}
    if isinstance(entry.get("heads"), dict):
        return {name: state for name, state in entry["heads"].items() if isinstance(state, dict)}
    return {default_branch: entry} if default_branch and entry.get("head_sha") else {}


def latest_scan(entry) -> dict | None:
    """The most recent branch rescan of a repository (what the panel shows), with its branch when known."""
    if isinstance(entry, dict) and not isinstance(entry.get("heads"), dict):
        return entry if entry.get("head_sha") else None
    states = [{**state, "branch": name} for name, state in _heads(entry).items()]
    return max(states, key=lambda state: str(state.get("at") or ""), default=None)


def branch_state(data_dir: Path, key: str, branch: str | None = None, *, default_branch: str | None = None) -> dict | None:
    entry = load(data_dir)["branches"].get(key)
    if branch is None:
        return latest_scan(entry)
    return _heads(entry, default_branch).get(branch)


def mark_branch(data_dir: Path, key: str, head_sha: str, run_id: str, branch: str, *, default_branch: str | None = None) -> None:
    with documents.lock(data_dir, "pr-watch"):
        payload = load(data_dir)
        heads = _heads(payload["branches"].get(key), default_branch)
        heads[branch] = {"head_sha": head_sha, "run_id": run_id, "at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        payload["branches"][key] = {"heads": heads}
        _save(data_dir, payload)


def branch_min_seconds() -> int:
    return 60 * max(10, int(os.environ.get("TAMANDUA_BRANCH_MIN_MINUTES", "60") or 60))


def interval() -> int:
    return max(60, int(os.environ.get("TAMANDUA_PR_POLL_SECONDS", "300") or 300))


def mark_closed(data_dir: Path, key: str, number: int) -> None:
    with documents.lock(data_dir, "pr-watch"):
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
        self._thread = threading.Thread(target=self._loop, name="tamandua-pr-watch", daemon=True)

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
        from tamandua.modules.findings.registry import pull_closed
        from tamandua.modules.integrations.github import GitHubAppError, pull_request
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
        from tamandua.modules.integrations.github import GitHubAppError, installation_repositories, open_pull_requests
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
        from tamandua.modules.integrations.installations import github_connections
        accounts = {row["account"].casefold() for row in github_connections(self.data_dir)
                    if isinstance(row.get("account"), str)}
        events.publish(RepositoriesListed(self.data_dir, repositories, accounts or None))
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
            targets = set(target_branches(config, by_uid[key].get("branch")))
            for pull in pulls:
                if pull["draft"] or not pull["head_sha"] or done.get(str(pull["number"]), {}).get("head_sha") == pull["head_sha"]:
                    continue
                if targets and pull.get("base_ref") not in targets:
                    continue
                if self.jobs.pending() >= 20:
                    return queued
                self.jobs.enqueue_pr_review(source_id=source_id, uid=key, pull=pull, installation_id=installation, requested_by="vigilante",
                                            default_branch=by_uid[key].get("branch"))
                queued += 1
        rescans = self._branches(by_uid)
        watched = sum(1 for config in load(self.data_dir)["repositories"].values() if config.get("enabled"))
        _log.info("pr_watch_poll", extra={"reason": f"{watched} repositorios vigilados, {queued} revisiones de PR y {rescans} "
                                                    "reanálisis de rama principal encolados"})
        return queued + rescans

    def _branches(self, by_uid: dict) -> int:
        """Rescans each target branch whose latest commit changed, pinned to that commit (with a pause between scans)."""
        from tamandua.modules.integrations.github import GitHubAppError, branch_head
        queued = 0
        now = datetime.now(timezone.utc)
        for key, config in load(self.data_dir)["repositories"].items():
            if not config.get("enabled") or not {**DEFAULTS, **config}.get("branch") or key not in by_uid:
                continue
            item = by_uid[key]
            if item.get("archived"):
                continue
            default = item.get("branch")
            for branch in target_branches(config, default):
                if queued >= BRANCH_PER_POLL or self.jobs.pending() >= BRANCH_QUEUE_LIMIT:
                    return queued
                last = branch_state(self.data_dir, key, branch, default_branch=default) or {}
                try:
                    if last.get("at") and (now - datetime.fromisoformat(last["at"])).total_seconds() < branch_min_seconds():
                        continue
                except ValueError:
                    pass
                try:
                    head = branch_head(item["installation_id"], item["name"], branch)
                except GitHubAppError as exc:
                    _log.warning("branch_head_failed", extra={"reason": f"{item['name']}@{branch}: {exc}"})
                    continue
                if head == last.get("head_sha"):
                    continue
                run = self.jobs.enqueue_repository_scan(
                    source_id=item["id"], source_name=item["name"], allow_osv_upload=False, context="", tokens={},
                    installation_id=item["installation_id"], uid=key, requested_by="vigilante", branch=branch, commit=head,
                    trigger={"kind": "branch", "branch": branch, "head_sha": head, "previous_sha": last.get("head_sha")})
                mark_branch(self.data_dir, key, head, run["id"], branch, default_branch=default)
                queued += 1
                _log.info("branch_rescan", extra={"reason": f"{item['name']}@{branch} {head[:7]}"})
        return queued
