"""Entorno de Alembic: usa la conexión que le pasa tamandua.app.database (o la URL configurada)."""

from alembic import context
from sqlalchemy import create_engine

from tamandua.app.database import tables
from tamandua.shared import db

tables()
target = db.metadata


def run() -> None:
    connection = context.config.attributes.get("connection")
    if connection is not None:
        context.configure(connection=connection, target_metadata=target, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()
        return
    with create_engine(context.config.get_main_option("sqlalchemy.url")).begin() as own:
        context.configure(connection=own, target_metadata=target, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


run()
