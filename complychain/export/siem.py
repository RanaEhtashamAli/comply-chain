"""
SIEMExporter — export ComplyChain events and scan results to SIEM formats.

Supported formats:
  - json   — Structured JSON (ELK / Datadog / Splunk HEC compatible)
  - cef    — Common Event Format (ArcSight, Splunk CIM)
  - leef   — Log Event Extended Format (IBM QRadar)

Syslog streaming uses stdlib logging.handlers.SysLogHandler (UDP/TCP).
No new dependencies — only stdlib json, socket, logging.

Usage:
    exporter = SIEMExporter()
    line = exporter.export_scan_result(scan_result, fmt="cef")
    exporter.stream_to_syslog("siem.corp.example.com", port=514)
"""

import json
import logging
import logging.handlers
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

_VERSION = "3.0.0"
_VENDOR = "ComplyChain"
_PRODUCT = "ComplyChain"

_SEVERITY_MAP: Dict[int, int] = {
    0:  0,  10: 1,  20: 2,  30: 3,  40: 4,
    50: 5,  60: 6,  70: 7,  80: 8,  90: 9,  100: 10,
}


def _risk_to_cef_severity(risk_score: int) -> int:
    for threshold in sorted(_SEVERITY_MAP.keys(), reverse=True):
        if risk_score >= threshold:
            return _SEVERITY_MAP[threshold]
    return 0


def _ts_iso(ts: Optional[float] = None) -> str:
    dt = datetime.fromtimestamp(ts or time.time(), tz=timezone.utc)
    return dt.isoformat(timespec="seconds")


def _escape_cef(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=").replace("\n", " ")


class SIEMExporter:
    """Converts ComplyChain data structures to SIEM-compatible log lines."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def export_event(self, event: Any, fmt: str = "json") -> str:
        d = event.to_dict() if hasattr(event, "to_dict") else dict(event)
        payload: Dict[str, Any] = {
            "event_id": d.get("event_id", ""),
            "event_type": d.get("event_type", ""),
            "timestamp": d.get("timestamp", time.time()),
            "payload": d.get("payload", {}),
        }
        return self._dispatch(payload, fmt, name=d.get("event_type", "event"))

    def export_scan_result(self, scan_result: dict, fmt: str = "json") -> str:
        payload: Dict[str, Any] = {
            "event_type": "scan_result",
            "timestamp": time.time(),
            "risk_score": scan_result.get("risk_score", 0),
            "threat_flags": scan_result.get("threat_flags", []),
            "fincen_compliance": scan_result.get("fincen_compliance", {}),
            "anomaly_score": scan_result.get("anomaly_score"),
        }
        return self._dispatch(payload, fmt, name="ThreatScan")

    def export_assessment(self, report: Any, fmt: str = "json") -> str:
        d = report.to_dict() if hasattr(report, "to_dict") else {}
        payload: Dict[str, Any] = {
            "event_type": "compliance_assessment",
            "timestamp": time.time(),
            "regulation_id": d.get("regulation_id", ""),
            "overall_status": d.get("overall_status", ""),
            "risk_score": d.get("risk_score", 0),
            "non_compliant_controls": [
                ctrl_id for ctrl_id, ctrl in d.get("controls", {}).items()
                if ctrl.get("status") == "NON_COMPLIANT"
            ],
        }
        return self._dispatch(payload, fmt, name="ComplianceAssessment")

    def stream_to_syslog(
        self,
        host: str,
        port: int = 514,
        protocol: str = "udp",
    ) -> None:
        """Attach a SysLogHandler to the root logger for SIEM streaming."""
        socktype = __import__("socket").SOCK_DGRAM if protocol == "udp" else __import__("socket").SOCK_STREAM
        handler = logging.handlers.SysLogHandler(address=(host, port), socktype=socktype)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logging.getLogger("complychain").addHandler(handler)

    # ------------------------------------------------------------------
    # Format dispatchers
    # ------------------------------------------------------------------

    def _dispatch(self, payload: Dict[str, Any], fmt: str, name: str) -> str:
        fmt = fmt.lower()
        if fmt == "json":
            return self._to_json(payload)
        if fmt == "cef":
            return self._to_cef(payload, name)
        if fmt == "leef":
            return self._to_leef(payload, name)
        raise ValueError(f"Unsupported SIEM format: '{fmt}'. Use 'json', 'cef', or 'leef'.")

    def _to_json(self, payload: Dict[str, Any]) -> str:
        out: Dict[str, Any] = {
            "@timestamp": _ts_iso(payload.get("timestamp")),
            "log": {"level": "warning" if payload.get("risk_score", 0) >= 50 else "info"},
            "event": {
                "action": payload.get("event_type", "unknown"),
                "outcome": "failure" if payload.get("risk_score", 0) >= 70 else "success",
            },
            "complychain": payload,
        }
        return json.dumps(out, default=str)

    def _to_cef(self, payload: Dict[str, Any], name: str) -> str:
        risk = int(payload.get("risk_score", 0))
        severity = _risk_to_cef_severity(risk)
        event_type = _escape_cef(payload.get("event_type", "unknown"))
        ext_parts = [
            f"rt={_ts_iso(payload.get('timestamp'))}",
            f"risk={risk}",
        ]
        flags = payload.get("threat_flags", [])
        if flags:
            ext_parts.append(f"flags={_escape_cef(','.join(str(f) for f in flags))}")
        fincen = payload.get("fincen_compliance", {})
        if fincen.get("sar_required"):
            ext_parts.append("sarRequired=true")
        if fincen.get("ctr_required"):
            ext_parts.append("ctrRequired=true")
        ext = " ".join(ext_parts)
        return (
            f"CEF:0|{_VENDOR}|{_PRODUCT}|{_VERSION}|{event_type}|"
            f"{_escape_cef(name)}|{severity}|{ext}"
        )

    def _to_leef(self, payload: Dict[str, Any], name: str) -> str:
        risk = int(payload.get("risk_score", 0))
        flags = payload.get("threat_flags", [])
        ts = _ts_iso(payload.get("timestamp"))
        attrs = [
            f"devTime={ts}",
            f"sev={_risk_to_cef_severity(risk)}",
            f"eventType={payload.get('event_type', 'unknown')}",
            f"risk={risk}",
            f"flags={','.join(str(f) for f in flags)}",
        ]
        fincen = payload.get("fincen_compliance", {})
        if fincen.get("sar_required"):
            attrs.append("sarRequired=true")
        if fincen.get("ctr_required"):
            attrs.append("ctrRequired=true")
        attrs_str = "\t".join(attrs)
        return f"LEEF:2.0|{_VENDOR}|{_PRODUCT}|{_VERSION}|{name}|\t{attrs_str}"
