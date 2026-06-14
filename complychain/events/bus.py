"""
EventBus — in-process publish/subscribe hub.

Handlers are called synchronously in the thread that calls emit().
Exceptions in handlers are caught and logged — they never propagate.
Thread-safe: RLock protects the handler registry.
"""

import logging
import threading
from collections import defaultdict
from typing import Callable, Dict, List, Optional

from .types import Event, EventType

_Handler = Callable[[Event], None]
_logger = logging.getLogger(__name__)


class EventBus:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._handlers: Dict[EventType, List[_Handler]] = defaultdict(list)

    def subscribe(self, event_type: EventType, handler: _Handler) -> None:
        with self._lock:
            self._handlers[event_type].append(handler)

    def unsubscribe(self, event_type: EventType, handler: _Handler) -> bool:
        with self._lock:
            try:
                self._handlers[event_type].remove(handler)
                return True
            except ValueError:
                return False

    def emit(self, event: Event) -> int:
        """Deliver event to all registered handlers. Returns count of handlers called."""
        with self._lock:
            handlers = list(self._handlers[event.event_type])
        called = 0
        for h in handlers:
            try:
                h(event)
                called += 1
            except Exception:
                _logger.exception(
                    "EventBus handler %s raised for event %s", h, event.event_type
                )
        return called

    def clear(self, event_type: Optional[EventType] = None) -> None:
        with self._lock:
            if event_type is None:
                self._handlers.clear()
            else:
                self._handlers[event_type].clear()


default_bus: EventBus = EventBus()
