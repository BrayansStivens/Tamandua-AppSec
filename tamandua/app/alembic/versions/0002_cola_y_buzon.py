"""cola de trabajos, latido de workers y buzón de avisos

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-26 00:03:59.269428
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade() -> None:
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
    op.create_table('workers',
    sa.Column('id', sa.Text(), nullable=False),
    sa.Column('heartbeat_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('docker', sa.Boolean(), server_default='false', nullable=False),
    sa.Column('version', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_workers'))
    )


def downgrade() -> None:
    op.drop_table('workers')
    op.drop_index('ix_outbox_due', table_name='outbox')
    op.drop_table('outbox')
    op.drop_index('ix_jobs_claim', table_name='jobs')
    op.drop_table('jobs')
