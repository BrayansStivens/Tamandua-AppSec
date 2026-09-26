"""Demo data: see Tamandua working without connecting GitHub or waiting for repositories.

`make demo` really analyzes (with the same engines as the panel) the deliberately vulnerable sample folders that
ship with the repository (`fixtures/sast-samples` and `fixtures/scanner-samples`), imports a sample threat model
and, if asked, analyzes a public image. Everything is marked as demo in the panel, with its context, in
`default_locale()`, and can be deleted like any other asset. It never makes findings up: if an engine is missing,
the analysis comes out incomplete and says so.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from tempfile import TemporaryDirectory

from tamandua.shared.i18n import LOCALES, default_locale, t, text

DEMO_SOURCE_ID = "local:demo-ejemplos"  # stable id: the onboarding checks look for it


def demo_source(locale: str | None = None) -> dict:
    return {"id": DEMO_SOURCE_ID, "name": t("demo.source_name", locale), "provider": "local"}


def model_name(locale: str | None = None) -> str:
    return t("demo.model_name", locale)


def models_folder(models: Path, locale: str | None = None) -> Path:
    """`<models>/<locale>/` when the examples come per language, else `<models>/`."""
    localized = models / (locale or default_locale())
    return localized if localized.is_dir() else models


def seed(data_dir: Path, *, fixtures: Path, models: Path | None = None, image: str | None = None, report=print) -> dict:
    from tamandua.modules.threats import model as tm
    from tamandua.modules.sources.repositories import snapshot_directory
    from tamandua.modules.scanning.repository import scan_repository
    from tamandua.modules.runs.store import save_repository_scan
    locale = default_locale()
    result: dict = {}
    (data_dir / "work").mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="demo-", dir=data_dir / "work") as temporary:
        combined, head = Path(temporary) / "src", Path(temporary) / "head"
        for folder in ("sast-samples", "scanner-samples"):
            if (fixtures / folder).is_dir():
                shutil.copytree(fixtures / folder, combined / folder)
        if not combined.is_dir():
            raise FileNotFoundError(t("cli.demo.no_fixtures", path=str(fixtures)))
        stats = snapshot_directory(combined, head)
        report(t("cli.demo.analyzing", count=stats["files"]))
        scan = scan_repository(head, {**demo_source(locale), "files": stats["files"], "snapshot": stats}, context=t("demo.context", locale), data_dir=data_dir,
                               progress=lambda level, message: report(f"  {text(message)}"))
        record = save_repository_scan(data_dir, {**scan, "requested_by": "demo"})
        result["code"] = {"id": record["id"], "status": record["status"], "findings": record["summary"].get("candidates", 0)}
        report(t("cli.demo.code_done", count=result["code"]["findings"], status=record["status"]))
    example = (models_folder(models, locale) / "stride.json") if models else None
    if example and example.is_file():
        name = model_name(locale)
        # Any language counts: switching the default locale must not import the demo model twice.
        if {item["name"] for item in tm.list_models(data_dir)} & {model_name(language) for language in LOCALES}:
            report(t("cli.demo.model_exists"))
        else:
            model = tm.from_portable(json.loads(example.read_text(encoding="utf-8")))
            model = {**model, "name": name}
            model.pop("relayout", None)
            saved = tm.save(data_dir, model, by="demo")
            result["threat_model"] = saved["id"]
            report(t("cli.demo.model_imported", name=name))
    if image:
        from tamandua.modules.scanning.image import check_registry_address, parse_reference, scan_image
        target = parse_reference(image)
        check_registry_address(target["registry"])
        report(t("cli.demo.analyzing_image", reference=target["reference"]))
        record = save_repository_scan(data_dir, {**scan_image(target, data_dir=data_dir), "requested_by": "demo"})
        result["image"] = {"id": record["id"], "status": record["status"], "findings": record["summary"].get("candidates", 0)}
        report(t("cli.demo.image_done", count=result["image"]["findings"], status=record["status"]))
    return result
