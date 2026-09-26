"""Datos de demostración: ver Tamandua funcionando sin conectar GitHub ni esperar a tener repositorios.

`make demo` analiza de verdad (con los mismos motores que el panel) las carpetas de ejemplos vulnerables a
propósito que trae el repositorio (`fixtures/sast-samples` y `fixtures/scanner-samples`), importa un modelo
de amenazas de ejemplo y, si se pide, analiza una imagen pública. Todo queda en el panel marcado como
«demo», con su contexto, y se puede borrar como cualquier otro activo. No inventa hallazgos: si un motor no
está disponible, el análisis sale incompleto y lo dice.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from tempfile import TemporaryDirectory

DEMO_SOURCE = {"id": "local:demo-ejemplos", "name": "demo · ejemplos vulnerables", "provider": "local"}
DEMO_CONTEXT = "Ejemplos vulnerables a propósito que trae Tamandua para probarlo: código, dependencias, secretos y un Dockerfile."
MODEL_NAME = "Demo · Portal de clientes (STRIDE)"


def seed(data_dir: Path, *, fixtures: Path, models: Path | None = None, image: str | None = None, report=print) -> dict:
    from . import threat_model as tm
    from .repository_sources import snapshot_directory
    from .repository_scan import scan_repository
    from .store import save_repository_scan
    result: dict = {}
    (data_dir / "work").mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="demo-", dir=data_dir / "work") as temporary:
        combined, head = Path(temporary) / "src", Path(temporary) / "head"
        for folder in ("sast-samples", "scanner-samples"):
            if (fixtures / folder).is_dir():
                shutil.copytree(fixtures / folder, combined / folder)
        if not combined.is_dir():
            raise FileNotFoundError(f"No encuentro los ejemplos en {fixtures}")
        stats = snapshot_directory(combined, head)
        report(f"Analizando {stats['files']} archivos de ejemplo con los motores de Tamandua…")
        scan = scan_repository(head, {**DEMO_SOURCE, "files": stats["files"], "snapshot": stats}, context=DEMO_CONTEXT, data_dir=data_dir,
                               progress=lambda level, message: report(f"  {message}"))
        record = save_repository_scan(data_dir, {**scan, "requested_by": "demo"})
        result["code"] = {"id": record["id"], "status": record["status"], "findings": record["summary"].get("candidates", 0)}
        report(f"Código: {result['code']['findings']} hallazgos ({record['status']}).")
    example = (models / "stride.json") if models else None
    if example and example.is_file():
        if any(item["name"] == MODEL_NAME for item in tm.list_models(data_dir)):
            report("Modelo de amenazas de ejemplo: ya estaba importado.")
        else:
            model = tm.from_portable(json.loads(example.read_text(encoding="utf-8")))
            model = {**model, "name": MODEL_NAME}
            model.pop("relayout", None)
            saved = tm.save(data_dir, model, by="demo")
            result["threat_model"] = saved["id"]
            report(f"Modelo de amenazas de ejemplo importado: «{MODEL_NAME}».")
    if image:
        from .image_scan import check_registry_address, parse_reference, scan_image
        target = parse_reference(image)
        check_registry_address(target["registry"])
        report(f"Analizando la imagen {target['reference']} (se lee del registro; puede tardar un par de minutos)…")
        record = save_repository_scan(data_dir, {**scan_image(target, data_dir=data_dir), "requested_by": "demo"})
        result["image"] = {"id": record["id"], "status": record["status"], "findings": record["summary"].get("candidates", 0)}
        report(f"Imagen: {result['image']['findings']} hallazgos ({record['status']}).")
    return result
