"""sign-in lock-out in the database

The progressive lock-out after failed sign-ins lived in each process's memory: with several API instances (or a
restart) an attacker got a fresh count. Now it is one row per key.

Revision ID: 0005
Revises: 0004
"""

from alembic import op
import sqlalchemy as sa

revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('auth_throttle',
    sa.Column('tenant_id', sa.Text(), server_default='default', nullable=False),
    sa.Column('key', sa.Text(), nullable=False),
    sa.Column('failures', sa.Integer(), server_default='0', nullable=False),
    sa.Column('until', sa.Float(), server_default='0', nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('tenant_id', 'key', name=op.f('pk_auth_throttle'))
    )


def downgrade() -> None:
    op.drop_table('auth_throttle')
