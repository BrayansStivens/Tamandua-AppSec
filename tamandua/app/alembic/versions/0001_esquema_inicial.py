"""esquema inicial

Revision ID: 0001
Revises: 
Create Date: 2026-09-26 00:43:16.909893
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('auth_challenges',
    sa.Column('tenant_id', sa.Text(), server_default='default', nullable=False),
    sa.Column('id', sa.Text(), nullable=False),
    sa.Column('user_id', sa.Text(), nullable=False),
    sa.Column('client', sa.Text(), nullable=False),
    sa.Column('failures', sa.Integer(), server_default='0', nullable=False),
    sa.Column('created_at', sa.Float(), nullable=False),
    sa.PrimaryKeyConstraint('tenant_id', 'id', name=op.f('pk_auth_challenges'))
    )
    op.create_table('documents',
    sa.Column('tenant_id', sa.Text(), server_default='default', nullable=False),
    sa.Column('name', sa.Text(), nullable=False),
    sa.Column('body', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('tenant_id', 'name', name=op.f('pk_documents'))
    )
    op.create_table('jobs',
    sa.Column('tenant_id', sa.Text(), server_default='default', nullable=False),
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('kind', sa.Text(), nullable=False),
    sa.Column('run_id', sa.String(length=32), nullable=True),
    sa.Column('payload', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('status', sa.Text(), server_default='queued', nullable=False),
    sa.Column('attempts', sa.Integer(), server_default='0', nullable=False),
    sa.Column('locked_by', sa.Text(), nullable=True),
    sa.Column('locked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('tenant_id', 'id', name=op.f('pk_jobs'))
    )
    op.create_index('ix_jobs_claim', 'jobs', ['tenant_id', 'status', 'created_at'], unique=False)
    op.create_table('outbox',
    sa.Column('tenant_id', sa.Text(), server_default='default', nullable=False),
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('channel_id', sa.Text(), nullable=False),
    sa.Column('payload', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('status', sa.Text(), server_default='pending', nullable=False),
    sa.Column('attempts', sa.Integer(), server_default='0', nullable=False),
    sa.Column('next_attempt_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('tenant_id', 'id', name=op.f('pk_outbox'))
    )
    op.create_index('ix_outbox_due', 'outbox', ['tenant_id', 'status', 'next_attempt_at'], unique=False)
    op.create_table('registry_assets',
    sa.Column('tenant_id', sa.Text(), server_default='default', nullable=False),
    sa.Column('asset_key', sa.Text(), nullable=False),
    sa.Column('name', sa.Text(), nullable=True),
    sa.Column('applied', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
    sa.PrimaryKeyConstraint('tenant_id', 'asset_key', name=op.f('pk_registry_assets'))
    )
    op.create_table('registry_findings',
    sa.Column('tenant_id', sa.Text(), server_default='default', nullable=False),
    sa.Column('asset_key', sa.Text(), nullable=False),
    sa.Column('fingerprint', sa.Text(), nullable=False),
    sa.Column('status', sa.Text(), nullable=False),
    sa.Column('cves', sa.ARRAY(sa.Text()), server_default='{}', nullable=False),
    sa.Column('entry', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('tenant_id', 'asset_key', 'fingerprint', name=op.f('pk_registry_findings'))
    )
    op.create_index('ix_registry_findings_cves', 'registry_findings', ['cves'], unique=False, postgresql_using='gin')
    op.create_index('ix_registry_findings_status', 'registry_findings', ['tenant_id', 'status'], unique=False)
    op.create_table('runs',
    sa.Column('tenant_id', sa.Text(), server_default='default', nullable=False),
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('type', sa.Text(), nullable=False),
    sa.Column('status', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('asset_key', sa.Text(), nullable=True),
    sa.Column('row', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('record', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('report', sa.Text(), nullable=True),
    sa.Column('sarif', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('tenant_id', 'id', name=op.f('pk_runs'))
    )
    op.create_index('ix_runs_asset', 'runs', ['tenant_id', 'asset_key'], unique=False)
    op.create_index('ix_runs_listing', 'runs', ['tenant_id', sa.literal_column('created_at DESC'), sa.literal_column('id DESC')], unique=False)
    op.create_index('ix_runs_status', 'runs', ['tenant_id', 'status'], unique=False)
    op.create_table('sessions',
    sa.Column('tenant_id', sa.Text(), server_default='default', nullable=False),
    sa.Column('id', sa.Text(), nullable=False),
    sa.Column('user_id', sa.Text(), nullable=False),
    sa.Column('expires_at', sa.Float(), nullable=False),
    sa.Column('record', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.PrimaryKeyConstraint('tenant_id', 'id', name=op.f('pk_sessions'))
    )
    op.create_index('ix_sessions_user', 'sessions', ['tenant_id', 'user_id'], unique=False)
    op.create_table('triage_decisions',
    sa.Column('tenant_id', sa.Text(), server_default='default', nullable=False),
    sa.Column('asset_key', sa.Text(), nullable=False),
    sa.Column('fingerprint', sa.Text(), nullable=False),
    sa.Column('status', sa.Text(), nullable=False),
    sa.Column('decision', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('tenant_id', 'asset_key', 'fingerprint', name=op.f('pk_triage_decisions'))
    )
    op.create_table('users',
    sa.Column('tenant_id', sa.Text(), server_default='default', nullable=False),
    sa.Column('id', sa.Text(), nullable=False),
    sa.Column('username', sa.Text(), nullable=False),
    sa.Column('position', sa.Integer(), server_default='0', nullable=False),
    sa.Column('record', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('tenant_id', 'id', name=op.f('pk_users')),
    sa.UniqueConstraint('tenant_id', 'username', name='uq_users_username')
    )
    op.create_table('workers',
    sa.Column('id', sa.Text(), nullable=False),
    sa.Column('heartbeat_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('docker', sa.Boolean(), server_default='false', nullable=False),
    sa.Column('version', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_workers'))
    )


def downgrade() -> None:
    op.drop_table('workers')
    op.drop_table('users')
    op.drop_table('triage_decisions')
    op.drop_index('ix_sessions_user', table_name='sessions')
    op.drop_table('sessions')
    op.drop_index('ix_runs_status', table_name='runs')
    op.drop_index('ix_runs_listing', table_name='runs')
    op.drop_index('ix_runs_asset', table_name='runs')
    op.drop_table('runs')
    op.drop_index('ix_registry_findings_status', table_name='registry_findings')
    op.drop_index('ix_registry_findings_cves', table_name='registry_findings', postgresql_using='gin')
    op.drop_table('registry_findings')
    op.drop_table('registry_assets')
    op.drop_index('ix_outbox_due', table_name='outbox')
    op.drop_table('outbox')
    op.drop_index('ix_jobs_claim', table_name='jobs')
    op.drop_table('jobs')
    op.drop_table('documents')
    op.drop_table('auth_challenges')
