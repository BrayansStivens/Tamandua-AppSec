"""formato actual de los datos: `target` en las ejecuciones y conexiones de GitHub siempre en lista

* El nombre del objetivo de una ejecución pasa de `fixture` a `target`.
* Una sola conexión de GitHub se guardaba como objeto y varias como lista: ahora siempre lista.

Revision ID: 0002
Revises: 0001
"""

from alembic import op

revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Sentencias literales (sin construir SQL con cadenas): una por columna.
    op.execute("""UPDATE runs SET "row" = ("row" - 'fixture') || jsonb_build_object('target', "row"->'fixture')
                  WHERE "row" ? 'fixture'""")
    op.execute("""UPDATE runs SET record = (record - 'fixture') || jsonb_build_object('target', record->'fixture')
                  WHERE record ? 'fixture'""")
    op.execute("""UPDATE documents SET body = jsonb_set(body, '{github}', jsonb_build_array(body->'github'))
                  WHERE name = 'integrations' AND jsonb_typeof(body->'github') = 'object'""")


def downgrade() -> None:
    op.execute("""UPDATE runs SET "row" = ("row" - 'target') || jsonb_build_object('fixture', "row"->'target')
                  WHERE "row" ? 'target'""")
    op.execute("""UPDATE runs SET record = (record - 'target') || jsonb_build_object('fixture', record->'target')
                  WHERE record ? 'target'""")
