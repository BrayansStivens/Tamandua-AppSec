"""Tamandua's command line: `scan` for terminals and CI, the panel, the worker and administration."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from tamandua.modules.identity.auth import PASSWORD_MIN, AuthError, Sessions, Users
from tamandua.modules.integrations.github import GitHubAppError, config as github_config
from tamandua.modules.integrations.installations import github_installations
from tamandua.app import wiring
from tamandua.app.data_migrations import DataTooNew, upgrade as upgrade_data
from tamandua.modules.integrations.ai_providers import PROVIDERS, check_provider, provider_status
from tamandua.modules.scanning.repository import scan_repository
from tamandua.modules.sources.repositories import SourceError, available_sources, snapshot_source
from tamandua.app.api.server import serve
from tamandua.modules.runs.store import list_runs, save_repository_scan
from tamandua.shared import settings
from tamandua.shared.i18n import localize, msg, t, text
from tamandua.shared.vault import VaultError


def _say(value) -> str:
    """CLI text: nobody asked in person, so it speaks TAMANDUA_DEFAULT_LOCALE."""
    return text(value)


def _detail(exc: Exception) -> str:
    return text(getattr(exc, "message", None) or str(exc))


def _json(value) -> str:
    return json.dumps(localize(value), ensure_ascii=False, indent=2)


def _scan_command(args) -> int:
    from tamandua.modules.runs.local import (EXIT_ERROR, EXIT_INCOMPLETE, EXIT_OK, LocalScanError, render_json, render_markdown,
                                             render_sarif, render_text, run)

    def progress(level: str, message: str) -> None:
        # Progress goes to stderr so stdout stays clean for JSON or SARIF.
        if not args.quiet:
            print(f"{'!' if level in ('warn', 'error') else '·'} {_say(message)}", file=sys.stderr, flush=True)

    try:
        result = run(args.path, data_dir=args.data_dir, base=args.base, baseline=not args.no_baseline, name=args.name,
                     fail_on=args.fail_on, allow_osv_upload=args.allow_osv_upload, progress=progress,
                     exclude=args.exclude)
    except (LocalScanError, OSError) as exc:
        print(t("cli.error", detail=_detail(exc)), file=sys.stderr)
        return EXIT_ERROR
    rendered = {"text": render_text, "json": render_json, "sarif": render_sarif}[args.format](result)
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
        if args.format != "text":
            print(render_text(result), end="", file=sys.stderr)
    else:
        print(rendered, end="")
    if args.summary:
        with args.summary.open("a", encoding="utf-8") as summary:  # append: $GITHUB_STEP_SUMMARY may hold other steps'
            summary.write(render_markdown(result))
    code = result["exit_code"]
    return EXIT_OK if code == EXIT_INCOMPLETE and args.allow_incomplete else code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tamandua", description="Tamandua: self-hosted application security")
    parser.add_argument("--data-dir", type=Path, default=None,
                        help="Local artifacts directory (default ./data; for `scan`, ~/.cache/tamandua)")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("runs", help="List saved runs")
    commands.add_parser("sources", help="List the repositories available in the workspace, GitHub and GitLab")
    repository = commands.add_parser("scan-repository", help="Analyze a selected repository without running its code")
    repository.add_argument("--source-id", required=True, help="ID returned by sources")
    repository.add_argument("--allow-osv-upload", action="store_true",
                            help="Allow sending dependency names and versions to api.osv.dev")
    local = commands.add_parser("scan", help="Analyze a local folder (terminal, pre-commit, CI)",
                                description="Analyzes a local folder without running its code. With --base it only reports what "
                                            "the change introduces. Exit codes: 0 pass · 1 findings at or above the threshold · "
                                            "2 usage error · 3 incomplete analysis.")
    local.add_argument("path", nargs="?", type=Path, default=Path("."), help="Folder to analyze (default: the current one)")
    local.add_argument("--base", help="Starting branch or commit (e.g. main or origin/main): only what the change introduces counts")
    local.add_argument("--no-baseline", action="store_true",
                       help="With --base, don't analyze the starting point: faster, but everything on changed lines counts")
    local.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "never"), default="high",
                       help="Severity that makes the scan fail (default high)")
    local.add_argument("--format", choices=("text", "json", "sarif"), default="text", help="Output format (default text)")
    local.add_argument("--output", type=Path, help="Write the result to a file instead of standard output")
    local.add_argument("--allow-incomplete", action="store_true",
                       help="Don't fail when an engine couldn't run (by default exits with 3: incomplete is not clean)")
    local.add_argument("--allow-osv-upload", action="store_true",
                       help="Allow external lookups (dependency names and versions to OSV and deps.dev)")
    local.add_argument("--quiet", action="store_true", help="No progress messages on standard error")
    local.add_argument("--exclude", action="append", default=[], metavar="PATTERN",
                       help="Path whose findings don't count (glob relative to the root: fixtures/**, **/testdata/**). Repeatable")
    local.add_argument("--name", help="Name to display (default: the folder's; useful inside a container)")
    local.add_argument("--summary", type=Path, metavar="FILE",
                       help="Also write a Markdown summary (what the change introduces and fixes), e.g. $GITHUB_STEP_SUMMARY")
    imported = commands.add_parser("import-sarif", help="Import another tool's SARIF 2.1.0 findings into an existing asset",
                                   description="Imports the findings of any tool (Semgrep, CodeQL, Snyk, Trivy…) into the registry of an "
                                               "asset Tamandua already knows. Several files are one import. A full import (the default) "
                                               "marks fixed what the same tool no longer reports. Exit codes: 0 imported · 2 usage, "
                                               "document or server error.")
    imported.add_argument("files", nargs="+", type=Path, metavar="FILE", help="SARIF 2.1.0 file(s)")
    imported.add_argument("--asset", required=True, help="Asset key or name, e.g. owner/repo")
    imported.add_argument("--tool", help="Tool name to record (default: each run's tool.driver.name)")
    imported.add_argument("--partial", action="store_true",
                          help="The tool looked at part of the asset: open and update, never mark anything fixed")
    imported.add_argument("--commit", help="Commit the results belong to")
    imported.add_argument("--branch", help="Branch the results belong to")
    imported.add_argument("--server", help="Send to this Tamandua (https://…) with the token in TAMANDUA_IMPORT_TOKEN; "
                                           "without it, import into the local database")
    image = commands.add_parser("scan-image", help="Analyze a container image from its registry, without running it")
    image.add_argument("--reference", required=True, help="registry/repository:tag, e.g. ghcr.io/acme/api:1.4")
    demo = commands.add_parser("demo", help="Load demo data: analyzes the vulnerable examples and imports a threat model")
    demo.add_argument("--fixtures", type=Path, default=Path("fixtures"), help="Folder with sast-samples and scanner-samples")
    demo.add_argument("--models", type=Path, default=Path("web/src/examples/threat-models"), help="Folder with the example models")
    demo.add_argument("--image", help="Also analyze this public image (e.g. nginx:1.21)")
    commands.add_parser("providers", help="Show which AI providers have a credential on the server")
    commands.add_parser("github-app", help="Status of this server's GitHub App (no secrets)")
    engines = commands.add_parser("engines", help="Status of the analysis engine images")
    engines.add_argument("--pull", action="store_true", help="Pull the missing ones by digest")
    ai_check = commands.add_parser("ai-check", help="Check authentication with OpenAI or Claude without spending tokens")
    ai_check.add_argument("--provider", choices=tuple(PROVIDERS), required=True)
    users = commands.add_parser("user", help="Manage panel users (operations task)")
    user_commands = users.add_subparsers(dest="user_command", required=True)
    create = user_commands.add_parser("create", help="Create a user; the first one should be --admin")
    create.add_argument("--username", required=True)
    create.add_argument("--display-name", default="")
    create.add_argument("--admin", action="store_true", help="Administrator role: connects providers and keys")
    create.add_argument("--password-stdin", action="store_true",
                        help="Read the password from stdin (automation); by default it's prompted without echo")
    user_commands.add_parser("list", help="List users, role, TOTP and last sign-in")
    for name, description in (("reset-password", "Set a new password and close their sessions"),
                              ("reset-totp", "Remove TOTP (lost device) and close their sessions"),
                              ("disable", "Block access and close their sessions"), ("enable", "Restore access")):
        action = user_commands.add_parser(name, help=description)
        action.add_argument("--username", required=True)
        if name == "reset-password":
            action.add_argument("--password-stdin", action="store_true")
    integrity = commands.add_parser("integrity", help="Check the database for orphan rows (reads only, unless --fix)")
    integrity.add_argument("--fix", action="store_true", help="Delete the orphan rows that are leftovers and print a summary")
    worker = commands.add_parser("worker", help="Run queued analyses and periodic tasks (the compose `worker` service)")
    worker.add_argument("--check", action="store_true", help="Health: 0 if this worker showed signs of life recently (healthcheck)")
    commands.add_parser("check-config", help="Check the settings in the environment (exit 1 if any is invalid)")
    rounds = commands.add_parser("periodic", help="Run one round of the due periodic tasks and exit (TAMANDUA_PERIODIC=external)")
    rounds.add_argument("--task", action="append", choices=("outbox", "pull_requests", "nvd", "advisories"),
                        help="Only this task (repeatable); by default every due task")
    commands.add_parser("setup-code", help="Show the one-time code to create the first administrator (while there is none)")
    panel = commands.add_parser("serve", help="Open the web panel")
    panel.add_argument("--port", type=int, default=8766)
    panel.add_argument("--bind", default=None, help="Listening interface; default 127.0.0.1 (or TAMANDUA_BIND)")
    return parser


def main(argv: list[str] | None = None) -> int:
    wiring.configure()
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        # Runs inside the user's repository: Tamandua's data (and the advisory cache) must not end up in it.
        args.data_dir = args.data_dir or (Path(settings.text("TAMANDUA_DATA_DIR")) if settings.is_set("TAMANDUA_DATA_DIR")
                                          else Path.home() / ".cache" / "tamandua")
        return _scan_command(args)
    if args.command == "import-sarif" and args.server:
        return _import_remote(args)  # a client: no database here
    args.data_dir = args.data_dir or Path(settings.text("TAMANDUA_DATA_DIR") or "data")
    if args.command == "check-config" or args.command == "serve" or (args.command == "worker" and not args.check):
        problems = settings.problems()
        if problems:
            print("\n".join([t("cli.settings.header"), *(f"  - {text(problem)}" for problem in problems)]), file=sys.stderr)
            return 1
        if args.command == "check-config":
            print(t("cli.settings.ok"))
            return 0
    try:
        if not (args.command == "worker" and args.check):  # healthcheck: migrates nothing, only reads the heartbeat
            upgrade_data(args.data_dir)
    except DataTooNew as error:
        print(_detail(error), file=sys.stderr)
        return 1
    try:
        if args.command == "worker":
            from tamandua.app.worker import healthy, run as run_worker
            if args.check:
                return 0 if healthy(args.data_dir) else 1
            run_worker(args.data_dir)
            return 0
        if args.command == "periodic":
            from tamandua.modules.runs import periodic
            from tamandua.modules.runs.jobs import ScanJobs
            outcome = periodic.run_round(args.data_dir, ScanJobs(args.data_dir, worker=False), here_only=False, only=args.task)
            print(_json(outcome))
            return 1 if outcome["failed"] else 0
        if args.command == "setup-code":
            from tamandua.modules.identity.auth import Authenticator
            code = Authenticator(args.data_dir).setup_code()
            print(t("cli.setup_code.code", code=code) if code else t("cli.setup_code.none"))
            return 0
        if args.command == "runs":
            print(_json(list_runs(args.data_dir)))
            return 0
        if args.command == "sources":
            print(_json(available_sources(None, github_installations(args.data_dir))))
            return 0
        if args.command == "scan-repository":
            (args.data_dir / "work").mkdir(parents=True, exist_ok=True)
            with TemporaryDirectory(prefix="snapshot-", dir=args.data_dir / "work") as temporary:
                listing = available_sources(None, github_installations(args.data_dir))
                selected = next((item for item in listing["sources"] if item["id"] == args.source_id), None)
                root, source = snapshot_source(args.source_id, Path(temporary), None,
                                               selected.get("installation_id") if selected else None)
                record = save_repository_scan(args.data_dir, scan_repository(root, source,
                                                                            allow_osv_upload=args.allow_osv_upload,
                                                                            data_dir=args.data_dir))
            print(_json({"id": record["id"], "status": record["status"], "source": record["source"]["name"], "summary": record["summary"]}))
            return 3 if record["status"] == "incomplete" else 2 if record["summary"]["candidates"] else 0
        if args.command == "scan-image":
            from tamandua.modules.scanning.image import ImageError, check_registry_address, parse_reference, scan_image
            try:
                target = parse_reference(args.reference)
                check_registry_address(target["registry"])
            except ImageError as exc:
                parser.exit(1, t("cli.error", detail=_detail(exc)) + "\n")
            record = save_repository_scan(args.data_dir, scan_image(target, data_dir=args.data_dir))
            print(_json({"id": record["id"], "status": record["status"], "image": target["reference"],
                         "summary": {key: record["summary"].get(key) for key in ("candidates", "severities", "agreement", "kev")}}))
            return 3 if record["status"] == "incomplete" else 2 if record["summary"]["candidates"] else 0
        if args.command == "demo":
            from tamandua.app.demo import seed
            from tamandua.modules.scanning.image import ImageError
            try:
                result = seed(args.data_dir, fixtures=args.fixtures, models=args.models, image=args.image,
                              report=lambda message: print(_say(message), flush=True))
            except (FileNotFoundError, ImageError) as exc:
                parser.exit(1, t("cli.error", detail=_detail(exc)) + "\n")
            print(t("cli.demo.ready"))
            return 0 if result.get("code", {}).get("status") == "completed" else 3
        if args.command == "providers":
            print(_json(provider_status()))
            return 0
        if args.command == "github-app":
            state = github_config()
            print(_json(state))
            return 0 if state["configured"] else 3
        if args.command == "engines":
            from tamandua.modules.scanning.engines import engine_status, pull_engines, socket_problem
            if socket_problem():
                print(_say(socket_problem()))
            rows = pull_engines(report=lambda message: print(_say(message), flush=True)) if args.pull else engine_status()
            for row in rows:
                state = t("cli.engines.ready") if row["ready"] else t("cli.engines.missing")
                print(f"{state:6} {row['name']} {row['version']}  {row['image']}" + (f"  ({_say(row['action'])})" if row.get("action") else ""))
            return 0 if all(row["ready"] for row in rows) else 3
        if args.command == "import-sarif":
            return _import_local(args)
        if args.command == "user":
            return _user_command(args)
        if args.command == "integrity":
            return _integrity_command(args)
        if args.command == "ai-check":
            result = check_provider(args.provider)
            print(_json(result))
            return 0 if result["status"] == "connected" else 3
        serve(args.data_dir, args.port, args.bind)
        return 0
    except (SourceError, GitHubAppError, VaultError, FileNotFoundError, ValueError) as exc:
        parser.exit(1, t("cli.error", detail=_detail(exc)) + "\n")


EXIT_IMPORT_ERROR = 2


def _sarif_document(files: list[Path]) -> dict:
    """The files as one SARIF document (their runs together): several files are one import."""
    from tamandua.modules.scanning.sarif_import import MAX_BYTES, SarifError
    runs: list = []
    total = 0
    for path in files:
        try:
            total += path.stat().st_size
            content = path.read_bytes() if total <= MAX_BYTES else b""
        except OSError as exc:
            raise SarifError(msg("cli.import_sarif.unreadable", file=str(path), detail=exc.strerror or str(exc))) from exc
        if total > MAX_BYTES:
            raise SarifError(msg("cli.import_sarif.too_large", max=MAX_BYTES // 1_000_000))
        try:
            document = json.loads(content)
        except (ValueError, RecursionError) as exc:
            raise SarifError(msg("cli.import_sarif.not_json", file=str(path))) from exc
        if not isinstance(document, dict) or document.get("version") != "2.1.0" or not isinstance(document.get("runs"), list):
            raise SarifError(msg("scanning.sarif.errors.version"))
        runs.extend(document["runs"])
    return {"version": "2.1.0", "runs": runs}


def _import_options(args) -> dict:
    return {"asset": args.asset, "scope": "partial" if args.partial else "full",
            **{name: getattr(args, name) for name in ("tool", "commit", "branch") if getattr(args, name) is not None}}


def _print_import(result: dict) -> None:
    print(t("cli.import_sarif.asset_line", name=result["name"], asset=result["asset"]))
    for run in result["runs"]:
        print(t("cli.import_sarif.run_full" if run["scope"] == "full" else "cli.import_sarif.run_partial", tool=run["tool"], id=run["id"],
                findings=run["findings"], opened=run["opened"], fixed=run["fixed"]))


def _import_local(args) -> int:
    from tamandua.modules.runs.imports import ImportRefused, import_sarif
    from tamandua.modules.scanning.sarif_import import SarifError
    try:
        options = _import_options(args)
        result = import_sarif(args.data_dir, _sarif_document(args.files), asset=options.pop("asset"), requested_by="cli", **options)
    except (SarifError, ImportRefused) as exc:
        print(t("cli.error", detail=_detail(exc)), file=sys.stderr)
        return EXIT_IMPORT_ERROR
    _print_import(result)
    return 0


def _server_url(server: str) -> str | None:
    """`server` + the CI route, if it is HTTPS (plain HTTP only for this machine)."""
    import ipaddress
    from urllib.parse import urlsplit
    parts = urlsplit(server.strip())
    host = parts.hostname or ""
    try:
        loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if not host or parts.query or parts.fragment or parts.username or not (parts.scheme == "https" or (parts.scheme == "http" and loopback)):
        return None
    return f"{server.strip().rstrip('/')}/api/ci/sarif"


def _import_remote(args) -> int:
    from urllib.error import HTTPError, URLError
    from urllib.request import Request
    from tamandua.modules.scanning.sarif_import import MAX_BYTES, SarifError
    from tamandua.shared.http import opener
    from tamandua.shared.i18n import default_locale
    token = settings.text("TAMANDUA_IMPORT_TOKEN")
    url = _server_url(args.server)
    if not token:
        print(t("cli.error", detail=t("cli.import_sarif.no_token")), file=sys.stderr)
        return EXIT_IMPORT_ERROR
    if url is None:
        print(t("cli.error", detail=t("cli.import_sarif.insecure_server", server=args.server)), file=sys.stderr)
        return EXIT_IMPORT_ERROR
    try:
        payload = json.dumps({**_import_options(args), "sarif": _sarif_document(args.files)}, ensure_ascii=False).encode("utf-8")
        if len(payload) > MAX_BYTES:
            raise SarifError(msg("cli.import_sarif.too_large", max=MAX_BYTES // 1_000_000))
    except SarifError as exc:
        print(t("cli.error", detail=_detail(exc)), file=sys.stderr)
        return EXIT_IMPORT_ERROR
    request = Request(url, data=payload, method="POST", headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": "application/json",
        "Accept-Language": default_locale()})
    try:
        with opener().open(request, timeout=300) as response:
            result = json.loads(response.read(1_000_000))
    except HTTPError as exc:
        try:
            detail = str(json.loads(exc.read(10_000)).get("error") or exc.reason)
        except (ValueError, AttributeError):
            detail = str(exc.reason)
        print(t("cli.error", detail=t("cli.import_sarif.http_error", status=exc.code, detail=detail[:300])), file=sys.stderr)
        return EXIT_IMPORT_ERROR
    except (URLError, OSError, ValueError) as exc:
        print(t("cli.error", detail=t("cli.import_sarif.unreachable", detail=str(getattr(exc, "reason", exc))[:300])), file=sys.stderr)
        return EXIT_IMPORT_ERROR
    _print_import(result)
    return 0


INTEGRITY_RELATIONS = {"registry_without_runs": "cli.integrity.registry_without_runs",
                    "triage_without_runs": "cli.integrity.triage_without_runs",
                    "runs_without_registry": "cli.integrity.runs_without_registry"}


def _integrity_command(args) -> int:
    from tamandua.app import integrity
    removed = integrity.fix(args.data_dir) if args.fix else {}
    found = integrity.check(args.data_dir)
    print(t("cli.integrity.title"))
    for relation, key in INTEGRITY_RELATIONS.items():
        line = f"  {t(key)}: {found[relation]}"
        if relation in removed:
            line += f"  ({t('cli.integrity.removed', count=removed[relation])})"
        elif relation in integrity.REPORTED and found[relation]:
            line += f"  ({t('cli.integrity.not_fixable')})"
        print(line)
    fixable = sum(found[relation] for relation in integrity.FIXABLE)
    if not any(found.values()):
        print(t("cli.integrity.clean"))
    elif fixable:
        print(t("cli.integrity.run_fix", count=fixable))
    return 0 if not any(found.values()) else 3


def _read_password(from_stdin: bool) -> str:
    # Never as an argument: it would end up in the shell history and the process list.
    if from_stdin:
        return sys.stdin.readline().rstrip("\n")
    first = getpass.getpass(t("cli.users.password_prompt", min=PASSWORD_MIN))
    if first != getpass.getpass(t("cli.users.password_repeat")):
        raise AuthError(msg("auth.errors.passwords_differ"))
    return first


def _user_command(args) -> int:
    users = Users(args.data_dir)
    if args.user_command == "list":
        print(_json(users.list()))
        return 0
    if args.user_command == "create":
        created = users.create(args.username, _read_password(args.password_stdin),
                               role="admin" if args.admin else "member", display_name=args.display_name)
        print(_json(created))
        print(t("cli.users.next_steps"), file=sys.stderr)
        return 0
    user = users.get(args.username)
    if user is None:
        raise AuthError(msg("auth.errors.user_not_found"))
    if args.user_command == "reset-password":
        users.set_password(user["id"], _read_password(args.password_stdin))
    elif args.user_command == "reset-totp":
        users.reset_totp(user["id"])
    elif args.user_command in ("disable", "enable"):
        users.set_disabled(user["id"], args.user_command == "disable")
    if args.user_command != "enable":
        closed = Sessions(args.data_dir).revoke_user(user["id"])
        print(t("cli.users.sessions_closed", count=closed), file=sys.stderr)
    print(_json(users.public(users.by_id(user["id"]))))
    return 0
