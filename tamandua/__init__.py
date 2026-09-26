"""Tamandua: seguridad de aplicaciones autoalojada.

Estructura (monolito modular):

* `app/`: composición. Servidor HTTP y rutas, migraciones de datos al arrancar, estáticos del panel.
* `modules/<contexto>/`: el negocio, un paquete por contexto (identity, sources, scanning, runs,
  findings, intel, compliance, reporting, integrations, pullrequests, threats, lab). Un módulo no
  importa de `app`.
* `shared/`: lo transversal sin negocio (logs, almacén cifrado, rutas). No importa de `modules`.
* `cli/`: la línea de comandos.

Los contratos entre capas los comprueba import-linter en el CI (pyproject.toml).
"""

from tamandua.version import VERSION

BRAND_NAME = "Tamandua"
__version__ = VERSION
