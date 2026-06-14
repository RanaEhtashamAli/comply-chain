"""
WebhookEmitter — delivers events via HTTP POST in a background daemon thread.

Configuration:
  COMPLYCHAIN_WEBHOOK_URLS   — comma-separated target URLs
  COMPLYCHAIN_WEBHOOK_SECRET — HMAC-SHA256 signing key (optional)
"""

import hashlib
import hmac
import json
import logging
import os
import queue
import threading
from typing import List, Optional

import requests

from .bus import EventBus, default_bus
from .types import Event, EventType

_logger = logging.getLogger(__name__)


class WebhookEmitter:
    """Subscribes to EventBus and delivers HTTP POST to configured URLs."""

    QUEUE_TIMEOUT = 5.0
    MAX_QUEUE_SIZE = 1000

    def __init__(
        self,
        urls: Optional[List[str]] = None,
        secret: Optional[str] = None,
        bus: Optional[EventBus] = None,
        timeout: float = 10.0,
    ) -> None:
        self._urls = urls if urls is not None else self._urls_from_env()
        self._secret = secret or os.environ.get("COMPLYCHAIN_WEBHOOK_SECRET")
        self._bus = bus or default_bus
        self._timeout = timeout
        self._queue: queue.Queue = queue.Queue(maxsize=self.MAX_QUEUE_SIZE)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @staticmethod
    def _urls_from_env() -> List[str]:
        raw = os.environ.get("COMPLYCHAIN_WEBHOOK_URLS", "")
        return [u.strip() for u in raw.split(",") if u.strip()]

    def _sign(self, body: bytes) -> str:
        if not self._secret:
            return ""
        return hmac.new(self._secret.encode(), body, hashlib.sha256).hexdigest()

    def _deliver(self, event: Event) -> None:
        if not self._urls:
            return
        body = json.dumps(event.to_dict()).encode()
        sig = self._sign(body)
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "ComplyChain-Webhook/1.0",
        }
        if sig:
            headers["X-ComplyChain-Signature"] = f"sha256={sig}"
        for url in self._urls:
            try:
                requests.post(url, data=body, headers=headers, timeout=self._timeout)
            except Exception:
                _logger.warning("Webhook delivery failed for %s", url)

    def _enqueue(self, event: Event) -> None:
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            _logger.warning("WebhookEmitter queue full — dropping event %s", event.event_id)

    def _worker(self) -> None:
        while not self._stop.is_set():
            try:
                event = self._queue.get(timeout=self.QUEUE_TIMEOUT)
                self._deliver(event)
                self._queue.task_done()
            except queue.Empty:
                continue

    def start(self) -> "WebhookEmitter":
        self._thread = threading.Thread(
            target=self._worker, daemon=True, name="complychain-webhook"
        )
        self._thread.start()
        for et in EventType:
            self._bus.subscribe(et, self._enqueue)
        return self

    def stop(self, drain_timeout: float = 5.0) -> None:
        for et in EventType:
            self._bus.unsubscribe(et, self._enqueue)
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=drain_timeout)
