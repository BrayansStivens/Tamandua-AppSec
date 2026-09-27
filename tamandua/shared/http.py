"""Outbound HTTP that never follows redirects.

A credential, a signed payload or an SSRF-checked destination must not travel to wherever a 3xx points: the redirect
comes back as an HTTPError with its status, and each caller decides what it means.
"""

from __future__ import annotations

from urllib.request import HTTPRedirectHandler, OpenerDirector, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def opener() -> OpenerDirector:
    return build_opener(NoRedirect)
