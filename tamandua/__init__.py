"""Tamandua: self-hosted application security.

Layout (modular monolith):

* `app/`: composition. HTTP server and routes, data migrations at startup, the panel's static files.
* `modules/<context>/`: the business logic, one package per context (identity, sources, scanning, runs,
  findings, intel, compliance, reporting, integrations, pullrequests, threats, lab). A module never
  imports from `app`.
* `shared/`: cross-cutting code with no business logic (logs, encrypted store, paths). Never imports from `modules`.
* `cli/`: the command line.

import-linter checks the contracts between layers in CI (pyproject.toml).
"""

from tamandua.version import VERSION

BRAND_NAME = "Tamandua"
__version__ = VERSION
