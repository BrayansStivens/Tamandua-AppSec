"""In-process domain events: one context says something happened, the contexts that care react.

Synchronous and ordered: `publish` returns once every subscriber ran, in subscription order, in the publisher's
thread and call (each subscriber opens its own transactions, exactly as a direct call would). The first error stops
the remaining subscribers and reaches the publisher, with a note naming the event and the subscriber.

The event types live in the publishing context; subscriptions are wired once per process by the composition root
(`tamandua/app/wiring.py`), so a context never imports the contexts that react to it. Publishing an event nobody
subscribed to raises: in a process that was not wired, reacting silently to nothing would lose data.
"""

from __future__ import annotations

import threading
from typing import Callable, TypeVar

Event = TypeVar("Event")


class Unhandled(LookupError):
    """An event with no subscriber: the process was not wired (see tamandua/app/wiring.py)."""


class Bus:
    def __init__(self) -> None:
        self._handlers: dict[type, list[Callable]] = {}
        self._lock = threading.Lock()

    def subscribe(self, kind: type[Event], handler: Callable[[Event], object]) -> None:
        with self._lock:
            self._handlers.setdefault(kind, []).append(handler)

    def subscribers(self, kind: type) -> tuple[Callable, ...]:
        with self._lock:
            return tuple(self._handlers.get(kind, ()))

    def publish(self, event: object) -> None:
        handlers = self.subscribers(type(event))
        if not handlers:
            raise Unhandled(f"No subscriber for {type(event).__name__}: this process was not wired")
        for handler in handlers:
            try:
                handler(event)
            except Exception as exc:
                exc.add_note(f"{type(event).__name__} subscriber {getattr(handler, '__qualname__', repr(handler))} failed")
                raise


_bus = Bus()
subscribe = _bus.subscribe
subscribers = _bus.subscribers
publish = _bus.publish
