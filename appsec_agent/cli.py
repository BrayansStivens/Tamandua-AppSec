"""Punto de entrada para evaluar el fixture y ver sus artefactos."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from .auth import AuthError, Sessions, Users
from .engine import scan_fixture
from .fixture import FixtureError, verify_fixture
from .github_app import GitHubAppError, config as github_config
from .integrations import github_installations
from .migrations import DataTooNew, upgrade as upgrade_data
from .providers import PROVIDERS, check_provider, provider_status
from .repository_scan import scan_repository
from .repository_sources import SourceError, available_sources, snapshot_source
from .server import serve
from .store import list_runs, save_repository_scan, save_run, save_scan


DEFAULT_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "tenant-api-lab"


def _scan_command(args) -> int:
    from .local_scan import EXIT_ERROR, EXIT_INCOMPLETE, EXIT_OK, LocalScanError, render_json, render_sarif, render_text, run

    def progress(level: str, message: str) -> None:
        # Progreso por la salida de errores: la estándar queda limpia para JSON o SARIF.
        if not args.quiet:
            print(f"{'!' if level in ('warn', 'error') else '·'} {message}", file=sys.stderr, flush=True)

    try:
        result = run(args.path, data_dir=args.data_dir, base=args.base, baseline=not args.no_baseline, name=args.name,
                     fail_on=args.fail_on, allow_osv_upload=args.allow_osv_upload, progress=progress,
                     exclude=args.exclude)
    except (LocalScanError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    rendered = {"text": render_text, "json": render_json, "sarif": render_sarif}[args.format](result)
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
        if args.format != "text":
            print(render_text(result), end="", file=sys.stderr)
    else:
        print(rendered, end="")
    code = result["exit_code"]
    return EXIT_OK if code == EXIT_INCOMPLETE and args.allow_incomplete else code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="appsec-agent", description="Prototipo local de evaluación AppSec")
    parser.add_argument("--data-dir", type=Path, default=None,
                        help="Directorio de artefactos locales (por defecto ./data; en `scan`, ~/.cache/tamandua)")
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify-fixture", help="Ejecutar los casos conocidos del laboratorio sintético")
    verify.add_argument("--fixture", type=Path, required=True)
    scan = commands.add_parser("scan-fixture", help="Detectar y reproducir cinco fallos en el laboratorio aprobado")
    scan.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    scan.add_argument("--variant", choices=("vulnerable", "fixed", "both"), default="both")
    commands.add_parser("runs", help="Listar ejecuciones guardadas")
    commands.add_parser("sources", help="Listar repositorios disponibles en el workspace, GitHub y GitLab")
    repository = commands.add_parser("scan-repository", help="Analizar un repositorio seleccionado sin ejecutar su código")
    repository.add_argument("--source-id", required=True, help="ID devuelto por sources")
    repository.add_argument("--allow-osv-upload", action="store_true",
                            help="Autorizar el envío de nombres y versiones de dependencias a api.osv.dev")
    local = commands.add_parser("scan", help="Analizar una carpeta local (terminal, pre-commit, CI)",
                                description="Analiza una carpeta local sin ejecutar su código. Con --base solo informa de lo que "
                                            "introduce el cambio. Salida: 0 pasa · 1 hay hallazgos del umbral o peores · "
                                            "2 error de uso · 3 análisis incompleto.")
    local.add_argument("path", nargs="?", type=Path, default=Path("."), help="Carpeta a analizar (por defecto, la actual)")
    local.add_argument("--base", help="Rama o commit de partida (p. ej. main u origin/main): solo cuenta lo que introduce el cambio")
    local.add_argument("--no-baseline", action="store_true",
                       help="Con --base, no analizar el punto de partida: más rápido, pero cuenta todo lo que cae en líneas cambiadas")
    local.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "never"), default="high",
                       help="Severidad desde la que falla (por defecto high)")
    local.add_argument("--format", choices=("text", "json", "sarif"), default="text", help="Formato de salida (por defecto text)")
    local.add_argument("--output", type=Path, help="Escribir el resultado en un archivo en lugar de la salida estándar")
    local.add_argument("--allow-incomplete", action="store_true",
                       help="No fallar si un motor no pudo ejecutarse (por defecto sale con 3: no equivale a limpio)")
    local.add_argument("--allow-osv-upload", action="store_true",
                       help="Autorizar consultas externas (nombres y versiones de dependencias a OSV y deps.dev)")
    local.add_argument("--quiet", action="store_true", help="Sin mensajes de progreso en la salida de errores")
    local.add_argument("--exclude", action="append", default=[], metavar="PATRÓN",
                       help="Ruta cuyos hallazgos no cuentan (glob relativo a la raíz: fixtures/**, **/testdata/**). Repetible")
    local.add_argument("--name", help="Nombre a mostrar (por defecto, el de la carpeta; útil dentro de un contenedor)")
    image = commands.add_parser("scan-image", help="Analizar una imagen de contenedor desde su registro, sin ejecutarla")
    image.add_argument("--reference", required=True, help="registro/repositorio:etiqueta, p. ej. ghcr.io/acme/api:1.4")
    demo = commands.add_parser("demo", help="Cargar datos de demostración: analiza los ejemplos vulnerables e importa un modelo de amenazas")
    demo.add_argument("--fixtures", type=Path, default=Path("fixtures"), help="Carpeta con sast-samples y scanner-samples")
    demo.add_argument("--models", type=Path, default=Path("web/src/examples/threat-models"), help="Carpeta con los modelos de ejemplo")
    demo.add_argument("--image", help="Además, analizar esta imagen pública (p. ej. nginx:1.21)")
    commands.add_parser("providers", help="Mostrar qué proveedores de IA tienen credencial en el servidor")
    commands.add_parser("github-app", help="Estado de la GitHub App de este servidor (sin secretos)")
    engines = commands.add_parser("engines", help="Estado de las imágenes de los motores de análisis")
    engines.add_argument("--pull", action="store_true", help="Descargar por digest las que falten")
    ai_check = commands.add_parser("ai-check", help="Comprobar autenticación con OpenAI o Claude sin generar tokens")
    ai_check.add_argument("--provider", choices=tuple(PROVIDERS), required=True)
    users = commands.add_parser("user", help="Gestionar usuarios del panel (tarea de operación)")
    user_commands = users.add_subparsers(dest="user_command", required=True)
    create = user_commands.add_parser("create", help="Crear un usuario; el primero debería ser --admin")
    create.add_argument("--username", required=True)
    create.add_argument("--display-name", default="")
    create.add_argument("--admin", action="store_true", help="Rol administrador: conecta proveedores y claves")
    create.add_argument("--password-stdin", action="store_true",
                        help="Leer la contraseña de stdin (automatización); por defecto se pide sin eco")
    user_commands.add_parser("list", help="Listar usuarios, rol, TOTP y último acceso")
    for name, text in (("reset-password", "Poner una contraseña nueva y cerrar sus sesiones"),
                       ("reset-totp", "Quitar el TOTP (dispositivo perdido) y cerrar sus sesiones"),
                       ("disable", "Bloquear el acceso y cerrar sus sesiones"), ("enable", "Reactivar el acceso")):
        action = user_commands.add_parser(name, help=text)
        action.add_argument("--username", required=True)
        if name == "reset-password":
            action.add_argument("--password-stdin", action="store_true")
    panel = commands.add_parser("serve", help="Abrir el panel web local de solo lectura")
    panel.add_argument("--port", type=int, default=8766)
    panel.add_argument("--bind", default=None, help="Interfaz de escucha; por defecto 127.0.0.1 (o APPSEC_AGENT_BIND)")
    args = parser.parse_args(argv)
    if args.command == "scan":
        # Se ejecuta dentro del repositorio del usuario: sus datos (y la caché de avisos) no van a parar a él.
        args.data_dir = args.data_dir or (Path(os.environ["APPSEC_AGENT_DATA_DIR"]) if os.environ.get("APPSEC_AGENT_DATA_DIR")
                                          else Path.home() / ".cache" / "tamandua")
        return _scan_command(args)
    args.data_dir = args.data_dir or Path("data")
    try:
        upgrade_data(args.data_dir)
    except DataTooNew as error:
        print(str(error), file=sys.stderr)
        return 1
    try:
        if args.command == "verify-fixture":
            record = save_run(args.data_dir, verify_fixture(args.fixture))
            print(json.dumps({"id": record["id"], "status": record["status"], "summary": record["summary"]}, ensure_ascii=False))
            return 0 if record["status"] == "completed" else 2
        if args.command == "scan-fixture":
            variants = ("vulnerable", "fixed") if args.variant == "both" else (args.variant,)
            records = [save_scan(args.data_dir, scan_fixture(args.fixture, variant)) for variant in variants]
            print(json.dumps([{"id": record["id"], "variant": record["variant"],
                               "status": record["status"], "summary": record["summary"]} for record in records],
                             ensure_ascii=False, indent=2))
            if any(record["status"] == "incomplete" for record in records):
                return 3
            return 2 if any(record["summary"]["confirmed"] for record in records) else 0
        if args.command == "runs":
            print(json.dumps(list_runs(args.data_dir), ensure_ascii=False, indent=2))
            return 0
        if args.command == "sources":
            print(json.dumps(available_sources(None, github_installations(args.data_dir), include_workspace=True),
                             ensure_ascii=False, indent=2))
            return 0
        if args.command == "scan-repository":
            (args.data_dir / "work").mkdir(parents=True, exist_ok=True)
            with TemporaryDirectory(prefix="snapshot-", dir=args.data_dir / "work") as temporary:
                listing = available_sources(None, github_installations(args.data_dir), include_workspace=True)
                selected = next((item for item in listing["sources"] if item["id"] == args.source_id), None)
                root, source = snapshot_source(args.source_id, Path(temporary), None,
                                               selected.get("installation_id") if selected else None)
                record = save_repository_scan(args.data_dir, scan_repository(root, source,
                                                                            allow_osv_upload=args.allow_osv_upload,
                                                                            data_dir=args.data_dir))
            print(json.dumps({"id": record["id"], "status": record["status"],
                              "source": record["source"]["name"], "summary": record["summary"]}, ensure_ascii=False, indent=2))
            return 3 if record["status"] == "incomplete" else 2 if record["summary"]["candidates"] else 0
        if args.command == "scan-image":
            from .image_scan import ImageError, check_registry_address, parse_reference, scan_image
            try:
                target = parse_reference(args.reference)
                check_registry_address(target["registry"])
            except ImageError as exc:
                parser.exit(1, f"Error: {exc}\n")
            record = save_repository_scan(args.data_dir, scan_image(target, data_dir=args.data_dir))
            print(json.dumps({"id": record["id"], "status": record["status"], "image": target["reference"],
                              "summary": {key: record["summary"].get(key) for key in ("candidates", "severities", "agreement", "kev")}},
                             ensure_ascii=False, indent=2))
            return 3 if record["status"] == "incomplete" else 2 if record["summary"]["candidates"] else 0
        if args.command == "demo":
            from .demo import seed
            from .image_scan import ImageError
            try:
                result = seed(args.data_dir, fixtures=args.fixtures, models=args.models, image=args.image,
                              report=lambda message: print(message, flush=True))
            except (FileNotFoundError, ImageError) as exc:
                parser.exit(1, f"Error: {exc}\n")
            print("Listo: abre el panel y mira Resumen, Hallazgos y Amenazas.")
            return 0 if result.get("code", {}).get("status") == "completed" else 3
        if args.command == "providers":
            print(json.dumps(provider_status(), ensure_ascii=False, indent=2))
            return 0
        if args.command == "github-app":
            state = github_config()
            print(json.dumps(state, ensure_ascii=False, indent=2))
            return 0 if state["configured"] else 3
        if args.command == "engines":
            from .scanners import engine_status, pull_engines, socket_problem
            if socket_problem():
                print(socket_problem())
            rows = pull_engines(report=lambda message: print(message, flush=True)) if args.pull else engine_status()
            for row in rows:
                print(f"{'listo' if row['ready'] else 'falta':6} {row['name']} {row['version']}  {row['image']}"
                      + (f"  ({row['action']})" if row.get("action") else ""))
            return 0 if all(row["ready"] for row in rows) else 3
        if args.command == "user":
            return _user_command(args)
        if args.command == "ai-check":
            result = check_provider(args.provider)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result["status"] == "connected" else 3
        serve(args.data_dir, args.port, args.bind)
        return 0
    except (FixtureError, SourceError, GitHubAppError, FileNotFoundError, ValueError) as exc:
        parser.exit(1, f"Error: {exc}\n")


def _read_password(from_stdin: bool) -> str:
    # Nunca por argumento: quedaría en el historial del shell y en la lista de procesos.
    if from_stdin:
        return sys.stdin.readline().rstrip("\n")
    first = getpass.getpass("Contraseña (mínimo 12 caracteres): ")
    if first != getpass.getpass("Repite la contraseña: "):
        raise AuthError("Las contraseñas no coinciden")
    return first


def _user_command(args) -> int:
    users = Users(args.data_dir)
    if args.user_command == "list":
        print(json.dumps(users.list(), ensure_ascii=False, indent=2))
        return 0
    if args.user_command == "create":
        created = users.create(args.username, _read_password(args.password_stdin),
                               role="admin" if args.admin else "member", display_name=args.display_name)
        print(json.dumps(created, ensure_ascii=False, indent=2))
        print("Inicia sesión en el panel y activa el TOTP desde Cuenta.", file=sys.stderr)
        return 0
    user = users.get(args.username)
    if user is None:
        raise AuthError("Usuario no encontrado")
    if args.user_command == "reset-password":
        users.set_password(user["id"], _read_password(args.password_stdin))
    elif args.user_command == "reset-totp":
        users.reset_totp(user["id"])
    elif args.user_command in ("disable", "enable"):
        users.set_disabled(user["id"], args.user_command == "disable")
    if args.user_command != "enable":
        closed = Sessions(args.data_dir).revoke_user(user["id"])
        print(f"Sesiones cerradas: {closed}", file=sys.stderr)
    print(json.dumps(users.public(users.by_id(user["id"])), ensure_ascii=False, indent=2))
    return 0
