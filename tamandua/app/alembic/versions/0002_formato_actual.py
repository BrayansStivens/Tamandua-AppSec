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
    for column in ("row", "record"):
        op.execute(f"""UPDATE runs SET "{column}" = ("{column}" - 'fixture') || jsonb_build_object('target', "{column}"->'fixture')
                       WHERE "{column}" ? 'fixture'""")
    op.execute("""UPDATE documents SET body = jsonb_set(body, '{github}', jsonb_build_array(body->'github'))
                  WHERE name = 'integrations' AND jsonb_typeof(body->'github') = 'object'""")


def downgrade() -> None:
    for column in ("row", "record"):
        op.execute(f"""UPDATE runs SET "{column}" = ("{column}" - 'target') || jsonb_build_object('fixture', "{column}"->'target')
                       WHERE "{column}" ? 'target'""")
