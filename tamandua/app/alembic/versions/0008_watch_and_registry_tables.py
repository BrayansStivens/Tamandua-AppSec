"""pull request watch and repository registry in tables

The `pr-watch` and `repo-registry` documents were rewritten whole on every change, and the reviewed pull requests in
the first one grow without end. Now: one row per repository and one per reviewed pull request. The
`watch_and_registry_to_tables` data migration moves what the documents held.

Revision ID: 0008
Revises: 0007
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0008'
down_revision = '0007'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('pr_watch',
    sa.Column('tenant_id', sa.Text(), server_default='default', nullable=False),
    sa.Column('asset_key', sa.Text(), nullable=False),
    sa.Column('config', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('branches', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('tenant_id', 'asset_key', name=op.f('pk_pr_watch'))
    )
    op.create_table('pr_reviews',
    sa.Column('tenant_id', sa.Text(), server_default='default', nullable=False),
    sa.Column('asset_key', sa.Text(), nullable=False),
    sa.Column('number', sa.Integer(), nullable=False),
    sa.Column('head_sha', sa.Text(), nullable=False),
    sa.Column('run_id', sa.String(length=32), nullable=False),
    sa.Column('closed', sa.Boolean(), server_default='false', nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('tenant_id', 'asset_key', 'number', name=op.f('pk_pr_reviews'))
    )
    op.create_table('repo_registry',
    sa.Column('tenant_id', sa.Text(), server_default='default', nullable=False),
    sa.Column('uid', sa.Text(), nullable=False),
    sa.Column('entry', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('tenant_id', 'uid', name=op.f('pk_repo_registry'))
    )


def downgrade() -> None:
    op.drop_table('repo_registry')
    op.drop_table('pr_reviews')
    op.drop_table('pr_watch')
