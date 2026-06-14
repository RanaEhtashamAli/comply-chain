"""Tests for EventBus, Event, EventType, SlackEmitter, WebhookEmitter."""

import json
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from complychain.events.bus import EventBus
from complychain.events.types import Event, EventType
from complychain.events.slack import SlackEmitter
from complychain.events.webhook import WebhookEmitter


# ---------------------------------------------------------------------------
# EventType + Event dataclass
# ---------------------------------------------------------------------------

def test_all_event_types_are_strings():
    for et in EventType:
        assert isinstance(et.value, str)


def test_event_has_unique_id():
    e1 = Event(EventType.THREAT_DETECTED, {"risk_score": 0.9})
    e2 = Event(EventType.THREAT_DETECTED, {"risk_score": 0.9})
    assert e1.event_id != e2.event_id


def test_event_timestamp_is_recent():
    before = time.time()
    e = Event(EventType.ASSESSMENT_COMPLETED, {})
    assert e.timestamp >= before


def test_event_to_dict():
    e = Event(EventType.SANCTION_HIT, {"entity": "ACME"}, event_id="abc", timestamp=1.0)
    d = e.to_dict()
    assert d["event_type"] == "sanction_hit"
    assert d["payload"] == {"entity": "ACME"}
    assert d["event_id"] == "abc"


# ---------------------------------------------------------------------------
# EventBus — subscribe / emit / unsubscribe / clear
# ---------------------------------------------------------------------------

def test_subscribe_and_emit():
    bus = EventBus()
    received = []
    bus.subscribe(EventType.THREAT_DETECTED, lambda e: received.append(e))
    evt = Event(EventType.THREAT_DETECTED, {"risk_score": 0.8})
    count = bus.emit(evt)
    assert count == 1
    assert len(received) == 1
    assert received[0] is evt


def test_emit_returns_zero_when_no_subscribers():
    bus = EventBus()
    count = bus.emit(Event(EventType.DRIFT_DETECTED, {}))
    assert count == 0


def test_handler_exception_does_not_propagate():
    bus = EventBus()

    def bad_handler(e):
        raise ValueError("oops")

    bus.subscribe(EventType.ASSESSMENT_COMPLETED, bad_handler)
    # must not raise
    count = bus.emit(Event(EventType.ASSESSMENT_COMPLETED, {}))
    assert count == 0  # raised, so not counted


def test_unsubscribe_removes_handler():
    bus = EventBus()
    received = []
    handler = lambda e: received.append(e)
    bus.subscribe(EventType.SANCTION_HIT, handler)
    removed = bus.unsubscribe(EventType.SANCTION_HIT, handler)
    assert removed is True
    bus.emit(Event(EventType.SANCTION_HIT, {}))
    assert received == []


def test_unsubscribe_returns_false_when_not_registered():
    bus = EventBus()
    handler = lambda e: None
    removed = bus.unsubscribe(EventType.THREAT_DETECTED, handler)
    assert removed is False


def test_clear_specific_event_type():
    bus = EventBus()
    received = []
    bus.subscribe(EventType.THREAT_DETECTED, lambda e: received.append(e))
    bus.subscribe(EventType.DRIFT_DETECTED, lambda e: received.append(e))
    bus.clear(EventType.THREAT_DETECTED)
    bus.emit(Event(EventType.THREAT_DETECTED, {}))
    bus.emit(Event(EventType.DRIFT_DETECTED, {}))
    assert len(received) == 1  # only DRIFT_DETECTED fired


def test_clear_all():
    bus = EventBus()
    received = []
    for et in EventType:
        bus.subscribe(et, lambda e: received.append(e))
    bus.clear()
    for et in EventType:
        bus.emit(Event(et, {}))
    assert received == []


def test_multiple_handlers_called_in_order():
    bus = EventBus()
    order = []
    bus.subscribe(EventType.COMPLIANCE_STATUS_CHANGED, lambda e: order.append(1))
    bus.subscribe(EventType.COMPLIANCE_STATUS_CHANGED, lambda e: order.append(2))
    bus.emit(Event(EventType.COMPLIANCE_STATUS_CHANGED, {}))
    assert order == [1, 2]


def test_thread_safe_emit():
    bus = EventBus()
    received = []
    lock = threading.Lock()

    def handler(e):
        with lock:
            received.append(e)

    bus.subscribe(EventType.THREAT_DETECTED, handler)
    evt = Event(EventType.THREAT_DETECTED, {})

    def emit_worker():
        for _ in range(10):
            bus.emit(evt)

    threads = [threading.Thread(target=emit_worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(received) == 40


# ---------------------------------------------------------------------------
# SlackEmitter
# ---------------------------------------------------------------------------

def test_slack_emitter_noop_without_url():
    """No URL → no HTTP calls, no error."""
    bus = EventBus()
    emitter = SlackEmitter(webhook_url="", bus=bus)
    # start/stop lifecycle
    emitter.start()
    bus.emit(Event(EventType.THREAT_DETECTED, {"risk_score": 0.9}))
    emitter.stop()


@patch("complychain.events.slack.requests.post")
def test_slack_emitter_sends_post(mock_post):
    bus = EventBus()
    emitter = SlackEmitter(webhook_url="https://hooks.example.com/T123", bus=bus)
    emitter.start()
    bus.emit(Event(EventType.THREAT_DETECTED, {"risk_score": 0.9, "threat_flags": []}))
    emitter.stop()
    mock_post.assert_called()
    payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
    assert "text" in payload


@patch("complychain.events.slack.requests.post")
def test_slack_format_assessment_completed(mock_post):
    bus = EventBus()
    emitter = SlackEmitter(webhook_url="https://hooks.example.com/T123", bus=bus)
    emitter.start()
    bus.emit(Event(EventType.ASSESSMENT_COMPLETED, {
        "regulation": "pci_dss", "risk_score": 0.3, "status": "COMPLIANT"
    }))
    emitter.stop()
    payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
    assert "Assessment completed" in payload["text"]


@patch("complychain.events.slack.requests.post")
def test_slack_format_missing_key_falls_back(mock_post):
    """If payload is missing a required template key, fallback text is used."""
    bus = EventBus()
    emitter = SlackEmitter(webhook_url="https://hooks.example.com/T123", bus=bus)
    emitter.start()
    # SANCTION_HIT template uses {entity} but we don't provide it
    bus.emit(Event(EventType.SANCTION_HIT, {}))
    emitter.stop()
    payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
    assert "sanction_hit" in payload["text"]


@patch("complychain.events.slack.requests.post", side_effect=ConnectionError("no net"))
def test_slack_delivery_error_does_not_raise(mock_post):
    bus = EventBus()
    emitter = SlackEmitter(webhook_url="https://hooks.example.com/T123", bus=bus)
    emitter.start()
    bus.emit(Event(EventType.DRIFT_DETECTED, {"drift_detected": True}))
    emitter.stop()


@patch("complychain.events.slack.requests.post")
def test_slack_emitter_stop_unsubscribes(mock_post):
    bus = EventBus()
    emitter = SlackEmitter(webhook_url="https://hooks.example.com/T123", bus=bus)
    emitter.start()
    emitter.stop()
    mock_post.reset_mock()
    bus.emit(Event(EventType.THREAT_DETECTED, {"risk_score": 0.5}))
    mock_post.assert_not_called()


# ---------------------------------------------------------------------------
# WebhookEmitter
# ---------------------------------------------------------------------------

def test_webhook_emitter_noop_without_urls():
    bus = EventBus()
    emitter = WebhookEmitter(urls=[], bus=bus)
    emitter.start()
    bus.emit(Event(EventType.THREAT_DETECTED, {}))
    emitter.stop()


@patch("complychain.events.webhook.requests.post")
def test_webhook_delivers_post(mock_post):
    bus = EventBus()
    emitter = WebhookEmitter(urls=["https://wh.example.com/endpoint"], bus=bus)
    emitter.start()
    bus.emit(Event(EventType.ASSESSMENT_COMPLETED, {"risk_score": 0.4}))
    # give background thread time to drain
    time.sleep(0.2)
    emitter.stop()
    mock_post.assert_called()
    kwargs = mock_post.call_args[1] if mock_post.call_args[1] else {}
    body = kwargs.get("data") or mock_post.call_args[0][1]
    payload = json.loads(body)
    assert payload["event_type"] == "assessment_completed"


@patch("complychain.events.webhook.requests.post")
def test_webhook_hmac_signature(mock_post):
    bus = EventBus()
    emitter = WebhookEmitter(
        urls=["https://wh.example.com/endpoint"],
        secret="my-secret",
        bus=bus,
    )
    emitter.start()
    bus.emit(Event(EventType.SANCTION_HIT, {"entity": "ACME"}))
    time.sleep(0.2)
    emitter.stop()
    headers = mock_post.call_args[1].get("headers") or {}
    assert "X-ComplyChain-Signature" in headers
    assert headers["X-ComplyChain-Signature"].startswith("sha256=")


@patch("complychain.events.webhook.requests.post", side_effect=ConnectionError("no net"))
def test_webhook_delivery_error_does_not_raise(mock_post):
    bus = EventBus()
    emitter = WebhookEmitter(urls=["https://wh.example.com/endpoint"], bus=bus)
    emitter.start()
    bus.emit(Event(EventType.DRIFT_DETECTED, {}))
    time.sleep(0.2)
    emitter.stop()


def test_webhook_urls_from_env(monkeypatch):
    monkeypatch.setenv("COMPLYCHAIN_WEBHOOK_URLS", "https://a.example.com, https://b.example.com")
    emitter = WebhookEmitter()
    assert "https://a.example.com" in emitter._urls
    assert "https://b.example.com" in emitter._urls


def test_webhook_empty_env_no_urls(monkeypatch):
    monkeypatch.delenv("COMPLYCHAIN_WEBHOOK_URLS", raising=False)
    emitter = WebhookEmitter()
    assert emitter._urls == []


def test_webhook_queue_full_drops_event():
    """When queue is full, event is dropped with a log warning — no exception."""
    import queue as _q
    bus = EventBus()
    emitter = WebhookEmitter(urls=["https://wh.example.com/"], bus=bus)
    # Fill the queue manually to force queue.Full on the next put_nowait
    for _ in range(emitter.MAX_QUEUE_SIZE):
        emitter._queue.put_nowait(Event(EventType.DRIFT_DETECTED, {}))
    # This must not raise even when the queue is full
    emitter._enqueue(Event(EventType.DRIFT_DETECTED, {}))


def test_webhook_stop_unsubscribes():
    bus = EventBus()
    emitter = WebhookEmitter(urls=["https://wh.example.com/"], bus=bus)
    emitter.start()
    emitter.stop()
    # After stop, no more enqueue subscriptions — queue stays empty
    assert emitter._queue.empty()
