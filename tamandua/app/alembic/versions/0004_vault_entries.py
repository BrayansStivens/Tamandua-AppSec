"""secrets vault in the database

The encrypted entries of `config/secrets.vault` move to `vault_entries` (same ciphertext, same associated data), so
every API instance and worker shares them without a shared disk. The file is imported by the `vault_to_database`
data migration, which needs the master key.

Revision ID: 0004
Revises: 0003
"""

from alembic import op
import sqlalchemy as sa

revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('vault_entries',
    sa.Column('tenant_id', sa.Text(), server_default='default', nullable=False),
    sa.Column('name', sa.Text(), nullable=False),
    sa.Column('nonce', sa.Text(), nullable=False),
    sa.Column('data', sa.Text(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('tenant_id', 'name', name=op.f('pk_vault_entries'))
    )


def downgrade() -> None:
    op.drop_table('vault_entries')
