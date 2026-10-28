"""Render supplied declarations without manufacturing measurement or authority."""
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from decimal import Decimal
from enum import Enum
from html import escape
import json
import math
from typing import Any

MODES = frozenset({"not_run", "static", "fixture", "actual"})
STATUSES = frozenset({"source_constructed", "replay_recorded", "unavailable", "refused", "mode_blocked"})


def to_data(value: Any, *, _depth: int = 0) -> Any:
    """Serialize trusted facade objects or JSON data; never import a data artifact."""
    if _depth > 64:
        raise ValueError("report nesting exceeds 64 levels")
    convert = lambda item: to_data(item, _depth=_depth + 1)
    if value is None or type(value) in (str, bool, int):
        return value
    if isinstance(value, Enum):
        return convert(value.value)
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("nonfinite report decimal")
        return str(value)
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("nonfinite report number")
        return value
    if hasattr(value, "model_dump"):
        return convert(value.model_dump(mode="json"))
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: convert(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise ValueError("report object keys must be strings")
        return {key: convert(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [convert(item) for item in value]
    raise ValueError(f"unsupported report value type: {type(value).__name__}")


def build_document(*, title: str, status: str, evidence_mode: str,
                   payload: Any = None, artifacts: Any = (), pointers: Any = (),
                   issues: Any = (), processing_mode: str = "not_run") -> dict[str, Any]:
    if (status not in STATUSES or evidence_mode not in MODES
            or processing_mode not in {"not_run", "replay", "oracle", "live"}):
        raise ValueError("unknown report status/evidence mode")
    data = to_data(payload)
    result = data.get("run_result", {}) if isinstance(data, dict) else {}
    if not isinstance(result, dict):
        result = {}
    return {
        "schema_version": 1,
        "title": title,
        "status": status,
        "processing_mode": "replay" if status == "replay_recorded" else processing_mode,
        "source_evidence_mode": evidence_mode,
        "runtime_status": "runtime_unverified",
        "admission_status": "pending",
        "authenticity_status": "not_established",
        "construction_exposure": "private_source_before_admission",
        "limitations": [
            "Hashes and resolved pointers establish local byte identity, not authentic execution or authorship.",
            "Fixture records are scripted data and cannot establish model efficacy or an authentic oracle pass.",
            "Recorded source and candidates are never executed by replay.",
            "Static hazards are warnings; finite-case observations are not an equivalence proof.",
        ],
        "current_live_run": {"status": "not_run", "model_id": None, "scheduled": None,
                             "passed": None, "failed": None, "success_rate": None,
                             "d_minus_c": None, "d_minus_r": None, "confidence_interval": None,
                             "known_usd": None, "reserved_unknown_usd": None, "cost_per_pass": None},
        "recorded_claims": {key: result.get(key) for key in (
            "status", "evidence_mode", "scheduled", "passed", "failed", "refused",
            "known_usd", "reserved_unknown_usd", "d_minus_c", "d_minus_r")},
        "coverage": {"status": "unknown", "paragraph": None, "statement": None,
                     "note": "No independently established coverage summary is supplied by this renderer."},
        "custody": {"status": "unverified", "seal_confirmed": None,
                    "note": "Artifact possession and receipt labels do not establish custody or appointments."},
        "failures_and_issues": to_data(issues),
        "artifacts": to_data(artifacts),
        "source_pointers": to_data(pointers),
        "payload": data,
    }


def render_json(document: Mapping[str, Any]) -> str:
    return json.dumps(to_data(document), ensure_ascii=True, sort_keys=True,
                      indent=2, allow_nan=False) + "\n"


def _block(title: str, value: Any) -> str:
    # Entire serialized content is escaped; no user URLs, CSS, attributes or HTML.
    return "<section><h2>" + escape(title) + "</h2><pre>" + escape(render_json({"data": value})) + "</pre></section>"


def _text_blocks(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    snippets = list(payload.get("source_and_candidate_text", ()))
    source = payload.get("source")
    if isinstance(source, dict):
        snippets.append(source)
    translation = payload.get("translation")
    if isinstance(translation, dict) and isinstance(translation.get("code"), str):
        snippets.append({"filename": "Generated Python — text only", "text": translation["code"]})
    blocks = []
    for item in snippets:
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            label = item.get("filename") or item.get("artifact_id") or "Source text"
            blocks.append("<h3>" + escape(str(label)) + "</h3><pre>" + escape(item["text"]) + "</pre>")
    return "<section><h2>Source/candidate text — never executed</h2>" + "".join(blocks) + "</section>" if blocks else ""


def render_html(document: Mapping[str, Any]) -> str:
    data = to_data(document)
    title = escape(str(data.get("title", "COBOL behavior map")))
    banner = escape(str(data.get("status", "unavailable")))
    mode = escape(str(data.get("source_evidence_mode", "not_run")))
    sections = [
        _block("Evidence and limitations", {key: data.get(key) for key in (
            "processing_mode", "source_evidence_mode", "runtime_status", "admission_status",
            "authenticity_status", "construction_exposure", "limitations")}),
        _block("Current live run — not run", data.get("current_live_run")),
        _block("Supplied recorded claims — unauthenticated", data.get("recorded_claims")),
        _block("Coverage — unknown", data.get("coverage")),
        _block("Custody — unverified", data.get("custody")),
        _block("Failures, refusals and issues", data.get("failures_and_issues")),
        _block("Artifact byte identities", data.get("artifacts")),
        _block("Source pointers", data.get("source_pointers")),
        _block("Source or supplied record payload", data.get("payload")),
        _text_blocks(data.get("payload")),
    ]
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
        "<title>" + title + "</title><style>body{font:16px system-ui;margin:2rem auto;padding:0 1rem;max-width:72rem;background:#f6f7fa;color:#162033}"
        "header,section{background:white;border:1px solid #d4dbe5;border-radius:.5rem;padding:1rem;margin:1rem 0}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:.85rem}h2{font-size:1.1rem}.notice{font-weight:600;color:#7a3600}</style>"
        "</head><body><header><h1>" + title + "</h1><p class=\"notice\">"
        + banner + " · source evidence: " + mode + " · runtime unverified · P2 pending</p></header>"
        + "".join(sections) + "</body></html>\n"
    )
