"""foreign keys where every write path creates the parent first

Added (composite, `tenant_id` + key; orphan rows are cleaned first and their counts logged):

* `sessions.user_id → users` and `auth_challenges.user_id → users`, ON DELETE CASCADE. Both are only written from a
  user loaded from `users`; a session or challenge of a user that no longer exists can't be used (`current()` and
  `second_factor()` already reject it), so orphans are deleted.
* `jobs.run_id → runs`, ON DELETE CASCADE. Every enqueue saves the run first; purging a repository deletes its runs,
  and a job without its run can't be executed (the worker loads the run first), so orphans are deleted. SET NULL was
  not an option: a queued job with no run would be claimed and fail. Adds `ix_jobs_run` for the cascade.
* `registry_findings.asset_key → registry_assets`, ON DELETE CASCADE. The registry writes the asset row and its
  findings in one transaction, and `forget_asset`/`rebuild` delete both. Orphan findings keep their history: the
  missing asset row is recreated (no name, no applied runs) instead of deleting them.

Left as logical relations (`tamandua doctor` reports them):

* `runs.asset_key → registry_assets`. A run is saved when it is queued; the registry row only appears when a finished
  run is applied. Queued, failed and non-finding runs never have one, and a registry rebuild empties the table.
* `triage_decisions (asset_key, fingerprint) → registry_findings`. Decisions must survive a registry rebuild (which
  deletes every registry row), `rename_asset` moves them to a new asset key before any run of that key is applied,
  and a decision can target a finding of a run the registry doesn't hold.

Revision ID: 0003
Revises: 0002
"""

from alembic import op
import sqlalchemy as sa

from tamandua.shared import log as logging_setup

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None

_log = logging_setup.get("database")

# Literal statements, no SQL assembled from strings.
CLEANUP = (
    ("sessions without user", """DELETE FROM sessions s WHERE NOT EXISTS
        (SELECT 1 FROM users u WHERE u.tenant_id = s.tenant_id AND u.id = s.user_id)"""),
    ("auth_challenges without user", """DELETE FROM auth_challenges c WHERE NOT EXISTS
        (SELECT 1 FROM users u WHERE u.tenant_id = c.tenant_id AND u.id = c.user_id)"""),
    ("jobs without run", """DELETE FROM jobs j WHERE j.run_id IS NOT NULL AND NOT EXISTS
        (SELECT 1 FROM runs r WHERE r.tenant_id = j.tenant_id AND r.id = j.run_id)"""),
    ("registry_assets recreated for orphan findings", """INSERT INTO registry_assets (tenant_id, asset_key)
        SELECT DISTINCT f.tenant_id, f.asset_key FROM registry_findings f WHERE NOT EXISTS
        (SELECT 1 FROM registry_assets a WHERE a.tenant_id = f.tenant_id AND a.asset_key = f.asset_key)"""),
)


def upgrade() -> None:
    connection = op.get_bind()
    # The lock adding the constraints needs anyway, taken before the cleanup: no orphan can slip in between.
    op.execute("LOCK TABLE users, sessions, auth_challenges, runs, jobs, registry_assets, registry_findings "
               "IN SHARE ROW EXCLUSIVE MODE")
    for label, statement in CLEANUP:
        count = connection.execute(sa.text(statement)).rowcount
        (_log.warning if count else _log.info)("orphans_cleaned", extra={"reason": f"{label}: {count}"})
    op.create_index('ix_jobs_run', 'jobs', ['tenant_id', 'run_id'], unique=False)
    op.create_foreign_key('fk_sessions_user', 'sessions', 'users', ['tenant_id', 'user_id'], ['tenant_id', 'id'], ondelete='CASCADE')
    op.create_foreign_key('fk_auth_challenges_user', 'auth_challenges', 'users', ['tenant_id', 'user_id'], ['tenant_id', 'id'],
                          ondelete='CASCADE')
    op.create_foreign_key('fk_jobs_run', 'jobs', 'runs', ['tenant_id', 'run_id'], ['tenant_id', 'id'], ondelete='CASCADE')
    op.create_foreign_key('fk_registry_findings_asset', 'registry_findings', 'registry_assets', ['tenant_id', 'asset_key'],
                          ['tenant_id', 'asset_key'], ondelete='CASCADE')


def downgrade() -> None:
    op.drop_constraint('fk_registry_findings_asset', 'registry_findings', type_='foreignkey')
    op.drop_constraint('fk_jobs_run', 'jobs', type_='foreignkey')
    op.drop_constraint('fk_auth_challenges_user', 'auth_challenges', type_='foreignkey')
    op.drop_constraint('fk_sessions_user', 'sessions', type_='foreignkey')
    op.drop_index('ix_jobs_run', table_name='jobs')
