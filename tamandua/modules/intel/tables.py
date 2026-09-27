"""The local copy of NVD with KEV and EPSS. Public reference data shared by the whole installation: no tenant."""

from sqlalchemy import Boolean, Column, Computed, Float, Index, Integer, Table, Text
from sqlalchemy.dialects.postgresql import TSVECTOR

from tamandua.shared.db import metadata

cves = Table(
    "intel_cves", metadata,
    Column("id", Text, primary_key=True),
    Column("year", Integer, nullable=False),
    Column("published", Text),
    Column("modified", Text),
    Column("status", Text),
    Column("severity", Text),
    Column("score", Float),
    Column("vector", Text),
    Column("version", Text),
    Column("description", Text),
    Column("cwe", Text),
    Column("refs", Text),
    # Free-text search on the identifier and the description ('simple': no stemming, as NVD wording needs).
    Column("search", TSVECTOR, Computed("to_tsvector('simple'::regconfig, ((id || ' '::text) || COALESCE(description, ''::text)))",
                                        persisted=True)),
)
Index("ix_intel_cves_published", cves.c.published)
Index("ix_intel_cves_year", cves.c.year, cves.c.published)
Index("ix_intel_cves_severity", cves.c.severity, cves.c.published)
Index("ix_intel_cves_search", cves.c.search, postgresql_using="gin")

kev = Table(
    "intel_kev", metadata,
    Column("id", Text, primary_key=True),
    Column("date_added", Text),
    Column("due_date", Text),
    Column("ransomware", Boolean, nullable=False, server_default="false"),
    Column("name", Text),
)
Index("ix_intel_kev_added", kev.c.date_added)

epss = Table(
    "intel_epss", metadata,
    Column("id", Text, primary_key=True),
    Column("score", Float),
    Column("percentile", Float),
)

# Where the NVD sync is (backfill page, last incremental window, feed versions loaded).
cve_state = Table(
    "intel_cve_state", metadata,
    Column("key", Text, primary_key=True),
    Column("value", Text),
)
