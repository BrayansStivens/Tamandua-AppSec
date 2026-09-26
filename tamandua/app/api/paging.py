"""Server-side paging of the typed routes: `limit`/`offset` in, `{items, total, limit, offset}` out."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, TypeVar

from fastapi import Query
from pydantic import BaseModel, Field

MAX_LIMIT = 100
MAX_OFFSET = 10_000  # beyond this, narrow the list with filters: avoids expensive OFFSETs

Item = TypeVar("Item")


class Page(BaseModel, Generic[Item]):
    items: list[Item] = Field(max_length=MAX_LIMIT)
    total: int
    limit: int
    offset: int


@dataclass(frozen=True)
class Paging:
    limit: int
    offset: int

    def slice(self, rows: list) -> dict:
        """One page of an already computed list."""
        return {"items": rows[self.offset:self.offset + self.limit], "total": len(rows), "limit": self.limit, "offset": self.offset}


def paging(default: int = 25):
    """Dependency: `limit` 1–100 and `offset` 0–MAX_OFFSET; anything else is the usual 400 (invalid parameters)."""
    def dependency(limit: int = Query(default, ge=1, le=MAX_LIMIT), offset: int = Query(0, ge=0, le=MAX_OFFSET)) -> Paging:
        return Paging(limit, offset)
    return dependency
