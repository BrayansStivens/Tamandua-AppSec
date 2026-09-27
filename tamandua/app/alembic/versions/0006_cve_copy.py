"""local NVD copy in the database

The CVE tracker's copy of NVD (with KEV and EPSS) moves from data/feeds/cves.sqlite to PostgreSQL, so an API with no
persistent disk (serverless) serves it too. Free-text search uses a generated tsvector with a GIN index. The SQLite
file of earlier versions is imported by the `cve_copy_to_database` data migration.

Revision ID: 0006
Revises: 0005
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0006'
down_revision = '0005'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('intel_cves',
    sa.Column('id', sa.Text(), nullable=False),
    sa.Column('year', sa.Integer(), nullable=False),
    sa.Column('published', sa.Text(), nullable=True),
    sa.Column('modified', sa.Text(), nullable=True),
    sa.Column('status', sa.Text(), nullable=True),
    sa.Column('severity', sa.Text(), nullable=True),
    sa.Column('score', sa.Float(), nullable=True),
    sa.Column('vector', sa.Text(), nullable=True),
    sa.Column('version', sa.Text(), nullable=True),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('cwe', sa.Text(), nullable=True),
    sa.Column('refs', sa.Text(), nullable=True),
    sa.Column('search', postgresql.TSVECTOR(), sa.Computed("to_tsvector('simple'::regconfig, ((id || ' '::text) || COALESCE(description, ''::text)))", persisted=True), nullable=True),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_intel_cves'))
    )
    op.create_index('ix_intel_cves_published', 'intel_cves', ['published'], unique=False)
    op.create_index('ix_intel_cves_year', 'intel_cves', ['year', 'published'], unique=False)
    op.create_index('ix_intel_cves_severity', 'intel_cves', ['severity', 'published'], unique=False)
    op.create_index('ix_intel_cves_search', 'intel_cves', ['search'], unique=False, postgresql_using='gin')
    op.create_table('intel_kev',
    sa.Column('id', sa.Text(), nullable=False),
    sa.Column('date_added', sa.Text(), nullable=True),
    sa.Column('due_date', sa.Text(), nullable=True),
    sa.Column('ransomware', sa.Boolean(), server_default='false', nullable=False),
    sa.Column('name', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_intel_kev'))
    )
    op.create_index('ix_intel_kev_added', 'intel_kev', ['date_added'], unique=False)
    op.create_table('intel_epss',
    sa.Column('id', sa.Text(), nullable=False),
    sa.Column('score', sa.Float(), nullable=True),
    sa.Column('percentile', sa.Float(), nullable=True),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_intel_epss'))
    )
    op.create_table('intel_cve_state',
    sa.Column('key', sa.Text(), nullable=False),
    sa.Column('value', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('key', name=op.f('pk_intel_cve_state'))
    )


def downgrade() -> None:
    op.drop_table('intel_cve_state')
    op.drop_table('intel_epss')
    op.drop_index('ix_intel_kev_added', table_name='intel_kev')
    op.drop_table('intel_kev')
    op.drop_index('ix_intel_cves_search', table_name='intel_cves', postgresql_using='gin')
    op.drop_index('ix_intel_cves_severity', table_name='intel_cves')
    op.drop_index('ix_intel_cves_year', table_name='intel_cves')
    op.drop_index('ix_intel_cves_published', table_name='intel_cves')
    op.drop_table('intel_cves')
