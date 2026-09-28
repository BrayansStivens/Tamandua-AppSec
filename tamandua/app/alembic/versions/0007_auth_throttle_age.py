"""sign-in lock-out: index by age

Idle keys are forgotten by the age of their last attempt; the index keeps that from reading the whole table, which an
attacker can fill with made-up usernames.

Revision ID: 0007
Revises: 0006
"""

from alembic import op

revision = '0007'
down_revision = '0006'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index('ix_auth_throttle_updated_at', 'auth_throttle', ['tenant_id', 'updated_at'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_auth_throttle_updated_at', table_name='auth_throttle')
