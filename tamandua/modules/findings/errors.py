"""Errors that reach a person: `message` is rendered in the reader's language; `str(exc)` is English, for logs."""

from __future__ import annotations

from tamandua.shared.i18n import text


class LocalizedError(Exception):
    def __init__(self, message):
        super().__init__(text(message, "en"))
        self.message = message
