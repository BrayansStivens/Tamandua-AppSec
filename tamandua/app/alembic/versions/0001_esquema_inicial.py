"""esquema inicial: ejecuciones, registro de hallazgos y triage

Revision ID: 0001
Revises: 
Create Date: 2026-09-25 23:52:33.631264
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
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
    op.create_table('triage_decisions',
    sa.Column('tenant_id', sa.Text(), server_default='default', nullable=False),
    sa.Column('asset_key', sa.Text(), nullable=False),
    sa.Column('fingerprint', sa.Text(), nullable=False),
    sa.Column('status', sa.Text(), nullable=False),
    sa.Column('decision', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('tenant_id', 'asset_key', 'fingerprint', name=op.f('pk_triage_decisions'))
    )


def downgrade() -> None:
    op.drop_table('triage_decisions')
    op.drop_index('ix_runs_status', table_name='runs')
    op.drop_index('ix_runs_listing', table_name='runs')
    op.drop_index('ix_runs_asset', table_name='runs')
    op.drop_table('runs')
    op.drop_index('ix_registry_findings_status', table_name='registry_findings')
    op.drop_index('ix_registry_findings_cves', table_name='registry_findings', postgresql_using='gin')
    op.drop_table('registry_findings')
    op.drop_table('registry_assets')
