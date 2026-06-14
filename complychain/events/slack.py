"""
SlackEmitter — sends Slack messages for ComplyChain events.

Configuration:
  COMPLYCHAIN_SLACK_WEBHOOK_URL — Slack Incoming Webhook URL

If the env var is not set, SlackEmitter is a no-op.
"""

import logging
import os
from typing import Optional

import requests

from .bus import EventBus, default_bus
from .types import Event, EventType

_logger = logging.getLogger(__name__)

_TEMPLATES = {
    EventType.THREAT_DETECTED:
        ":rotating_light: *Threat detected* | risk_score={risk_score}",
    EventType.SANCTION_HIT:
        ":no_entry: *Sanctions match* | entity={entity}",
    EventType.COMPLIANCE_STATUS_CHANGED:
        ":clipboard: *Compliance status changed* | {regulation} → {status}",
    EventType.ASSESSMENT_COMPLETED:
        ":white_check_mark: *Assessment completed* | {regulation} risk={risk_score:.2f}",
    EventType.DRIFT_DETECTED:
        ":chart_with_upwards_trend: *Model drift detected* | drift_detected={drift_detected}",
}


class SlackEmitter:
    """Sends Slack Block Kit messages for each event type."""

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        bus: Optional[EventBus] = None,
        timeout: float = 5.0,
    ) -> None:
        self._url = webhook_url or os.environ.get("COMPLYCHAIN_SLACK_WEBHOOK_URL", "")
        self._bus = bus or default_bus
        self._timeout = timeout
        if not self._url:
            _logger.warning(
                "SlackEmitter: COMPLYCHAIN_SLACK_WEBHOOK_URL not set — Slack notifications disabled."
            )

    def _format(self, event: Event) -> dict:
        template = _TEMPLATES.get(event.event_type, "ComplyChain event: {event_type}")
        try:
            text = template.format(event_type=event.event_type.value, **event.payload)
        except KeyError:
            text = f"ComplyChain {event.event_type.value} event"
        return {
            "text": text,
            "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text}}],
        }

    def _send(self, event: Event) -> None:
        if not self._url:
            return
        try:
            requests.post(self._url, json=self._format(event), timeout=self._timeout)
        except Exception:
            _logger.warning("Slack delivery failed for event %s", event.event_id)

    def start(self) -> "SlackEmitter":
        for et in EventType:
            self._bus.subscribe(et, self._send)
        return self

    def stop(self) -> None:
        for et in EventType:
            self._bus.unsubscribe(et, self._send)
