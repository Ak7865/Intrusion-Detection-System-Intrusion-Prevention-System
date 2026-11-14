from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import joblib
import numpy as np
import pandas as pd
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[2]
PROJECT_ROOT = Path(os.environ.get("IPS_PROJECT_ROOT", str(ROOT)))
HOST = os.environ.get("IPS_API_HOST", "0.0.0.0")
PORT = int(os.environ.get("IPS_API_PORT", "8765"))
EVENT_DIR = Path(os.environ.get("IPS_EVENT_DIR", str(PROJECT_ROOT / "runtime" / "events")))
EVENT_FILE = EVENT_DIR / "hyperledger_events.jsonl"

ORG_ID = os.environ.get("IPS_ORG_ID", "ORG_A")
ORG_NAME = os.environ.get("IPS_ORG_NAME", "Organisation A")
NODE_ID = os.environ.get("IPS_NODE_ID", "NODE_A")
MODEL_VERSION = os.environ.get("IPS_MODEL_VERSION", "1.0")

# Live CICFlowMeter feature equivalence has not yet been experimentally verified.
FEATURE_COMPATIBILITY = "NOT_VERIFIED"

FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Flow Bytes/s", "Flow Packets/s",
    "Fwd Packets/s", "Bwd Packets/s", "Down/Up Ratio"
]

ALERT_CACHE_SECONDS = 180
MAX_REQUEST_BYTES = 2_000_000

# Load local API configuration.
LOCAL_ENV_FILE = Path(__file__).with_name(".env")
if LOCAL_ENV_FILE.is_file():
    for line in LOCAL_ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(
                key.strip(), value.strip().strip('"').strip("'")
            )

try:
    from suricata_rule_generator import (
        generate_rule,
        handle_ml_detection,
        handle_suricata_detection
    )
except ImportError:
    try:
        from integration.windows_ml_service.suricata_rule_generator import (
            generate_rule,
            handle_ml_detection,
            handle_suricata_detection
        )
    except ImportError:
        generate_rule = None
        handle_ml_detection = None
        handle_suricata_detection = None

try:
    _raw_node_hashes = json.loads(
        os.environ.get("IPS_NODE_TOKEN_HASHES", "{}")
    )
except json.JSONDecodeError as exc:
    raise RuntimeError("Invalid IPS_NODE_TOKEN_HASHES JSON") from exc

if not isinstance(_raw_node_hashes, dict):
    raise RuntimeError("IPS_NODE_TOKEN_HASHES must be a JSON object")

NODE_TOKEN_HASHES: dict[str, str] = {}

for node_id, digest in _raw_node_hashes.items():
    if node_id not in {"NODE_A", "NODE_B", "NODE_C"}:
        raise RuntimeError(f"Unknown node identity: {node_id}")
    if not isinstance(digest, str) or len(digest) != 64:
        raise RuntimeError(f"Invalid SHA-256 hash for {node_id}")
    if any(c not in "0123456789abcdefABCDEF" for c in digest):
        raise RuntimeError(f"Invalid SHA-256 hash for {node_id}")
    NODE_TOKEN_HASHES[node_id] = digest.lower()

if len(set(NODE_TOKEN_HASHES.values())) != len(NODE_TOKEN_HASHES):
    raise RuntimeError("Duplicate node credentials are not permitted")


def authenticate_node(authorization: str) -> str | None:
    scheme, separator, token = authorization.partition(" ")

    if not separator or scheme.lower() != "bearer" or not token.strip():
        return None

    candidate = hashlib.sha256(
        token.strip().encode("utf-8")
    ).hexdigest()

    for node_id, expected_hash in NODE_TOKEN_HASHES.items():
        if hmac.compare_digest(candidate, expected_hash):
            return node_id

    return None
alerts: dict[tuple, dict[str, Any]] = {}
seen_alerts: dict[tuple, float] = {}
alert_lock = threading.Lock()
event_lock = threading.Lock()

# ── Node registry (populated on first authenticated POST) ──────────────────────
_node_registry: dict[str, dict[str, Any]] = {}
_node_lock = threading.Lock()

ADMIN_API_KEY = os.environ.get("IPS_ADMIN_API_KEY", "")

# ── Blocked IP store ───────────────────────────────────────────────────────────
BLOCKED_IPS_FILE = PROJECT_ROOT / "runtime" / "blocked_ips.json"
_blocked_ips: dict[str, dict[str, Any]] = {}
_blocked_lock = threading.Lock()


def _load_blocked_ips() -> None:
    """Load persisted blocked IPs from JSON file on startup."""
    global _blocked_ips
    if BLOCKED_IPS_FILE.is_file():
        try:
            data = json.loads(BLOCKED_IPS_FILE.read_text(encoding="utf-8"))
            _blocked_ips = {k: v for k, v in data.items()}
        except Exception:
            _blocked_ips = {}


def _save_blocked_ips() -> None:
    """Persist blocked IPs to JSON file (call under _blocked_lock)."""
    try:
        BLOCKED_IPS_FILE.parent.mkdir(parents=True, exist_ok=True)
        BLOCKED_IPS_FILE.write_text(
            json.dumps(_blocked_ips, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
    except Exception as exc:
        print(f"[blocked_ips] Failed to persist: {exc}", flush=True)


def block_ip(ip: str, reason: str, duration_minutes: int = 0, blocked_by: str = "ADMIN") -> dict[str, Any]:
    """Block an IP. duration_minutes=0 means permanent."""
    now = utcnow()
    expires_at = None
    if duration_minutes > 0:
        from datetime import timedelta
        exp = datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)
        expires_at = exp.isoformat().replace("+00:00", "Z")
    entry = {
        "ip": ip, "reason": reason, "blocked_at": now,
        "blocked_by": blocked_by, "expires_at": expires_at
    }
    with _blocked_lock:
        _blocked_ips[ip] = entry
        _save_blocked_ips()
    return entry


def unblock_ip(ip: str) -> bool:
    """Unblock an IP. Returns True if it was blocked."""
    with _blocked_lock:
        removed = _blocked_ips.pop(ip, None)
        if removed:
            _save_blocked_ips()
        return removed is not None


def get_blocked_ips() -> list[dict[str, Any]]:
    """Return list of currently blocked IPs (auto-removes expired ones)."""
    now_dt = datetime.now(timezone.utc)
    with _blocked_lock:
        expired = [
            ip for ip, entry in _blocked_ips.items()
            if entry.get("expires_at") and
            datetime.fromisoformat(entry["expires_at"].replace("Z", "+00:00")) < now_dt
        ]
        for ip in expired:
            _blocked_ips.pop(ip, None)
        if expired:
            _save_blocked_ips()
        return list(_blocked_ips.values())


_load_blocked_ips()

# ── Blocked IP store (in-memory + persisted JSON) ──────────────────────────────
BLOCKED_IPS_FILE = PROJECT_ROOT / "runtime" / "blocked_ips.json"
_blocked_ips: dict[str, dict] = {}  # ip -> {ip, reason, blocked_at, blocked_by, expires_at or None}
_blocked_lock = threading.Lock()


def _load_blocked_ips() -> None:
    """Load blocked IPs from persisted JSON on startup."""
    global _blocked_ips
    if BLOCKED_IPS_FILE.is_file():
        try:
            data = json.loads(BLOCKED_IPS_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                with _blocked_lock:
                    _blocked_ips = data
        except (json.JSONDecodeError, OSError):
            pass


def _save_blocked_ips() -> None:
    """Persist blocked IPs to JSON. Must be called with _blocked_lock held."""
    try:
        BLOCKED_IPS_FILE.parent.mkdir(parents=True, exist_ok=True)
        BLOCKED_IPS_FILE.write_text(
            json.dumps(_blocked_ips, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )
    except OSError:
        pass


def _apply_node_approval(node_id: str, entry: dict[str, Any]) -> None:
    """Set initial approval_status when a node first connects. Called with _node_lock held."""
    if "approval_status" in entry:
        return  # Already initialised
    approved_count = sum(
        1 for n in _node_registry.values()
        if n.get("approval_status") == "APPROVED"
    )
    now = utcnow()
    entry["join_requested_at"] = now
    entry["received_approvals"] = []
    if approved_count == 0:
        entry["approval_status"] = "APPROVED"
        entry["required_approvals"] = 0
    else:
        entry["approval_status"] = "PENDING_APPROVAL"
        entry["required_approvals"] = approved_count


def _update_node_heartbeat(node_id: str) -> None:
    with _node_lock:
        entry = _node_registry.get(node_id, {})
        entry["node_id"] = node_id
        entry["last_heartbeat"] = utcnow()
        entry["status"] = "online"
        entry.setdefault("role", "sensor")
        entry.setdefault("first_seen", utcnow())
        _apply_node_approval(node_id, entry)
        _node_registry[node_id] = entry


def _read_events_page(page: int, page_size: int, detection_method: str = "") -> dict[str, Any]:
    """Read events from the JSONL file and return a paginated page."""
    events: list[dict[str, Any]] = []
    if EVENT_FILE.is_file():
        try:
            raw = EVENT_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            raw = []
        for line in reversed(raw):
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue
            if detection_method:
                src = evt.get("detection", {}).get("detection_source", "")
                if src != detection_method:
                    continue
            events.append(evt)

    total = len(events)
    start = (page - 1) * page_size
    end = start + page_size
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "events": events[start:end]
    }


def _build_stats() -> dict[str, Any]:
    """Compute dashboard stats from the JSONL file."""
    suricata_count = 0
    ml_count = 0
    informational_count = 0
    review_count = 0
    attack_count = 0
    total = 0
    recent: list[dict[str, Any]] = []

    if EVENT_FILE.is_file():
        try:
            lines = EVENT_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            lines = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue
            total += 1
            det = evt.get("detection", {})
            src = det.get("detection_source") or ""
            status = det.get("classification_status") or ""
            if src == "SURICATA":
                suricata_count += 1
            elif src == "ML_MODEL":
                ml_count += 1
            if status == "INFORMATIONAL":
                informational_count += 1
            elif status in ("REQUIRES_REVIEW", ""):
                # Legacy events without classification_status are treated as requiring review
                review_count += 1
            if det.get("attack_detected"):
                attack_count += 1

        # Most recent 10 events (last lines)
        for line in reversed(lines[-20:]):
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue
            recent.append(evt)
            if len(recent) >= 10:
                break

    with _node_lock:
        node_list = list(_node_registry.values())

    return {
        "total_events": total,
        "suricata_detections": suricata_count,
        "ml_detections": ml_count,
        "informational_alerts": informational_count,
        "events_requiring_review": review_count,
        "attack_events": attack_count,
        "active_nodes": len(node_list),
        "recent_events": recent
    }


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalise_protocol(value: Any) -> str:
    text = str(value or "").strip().lower()
    return {
        "6": "tcp", "tcp": "tcp",
        "17": "udp", "udp": "udp",
        "1": "icmp", "icmp": "icmp",
        "58": "icmpv6", "icmpv6": "icmpv6"
    }.get(text, text)


def tuple_keys(src: Any, dst: Any, sport: Any, dport: Any, proto: Any):
    protocol = normalise_protocol(proto)
    src_port, dst_port = int(sport or 0), int(dport or 0)
    return (
        (str(src or ""), str(dst or ""), src_port, dst_port, protocol),
        (str(dst or ""), str(src or ""), dst_port, src_port, protocol)
    )


def append_event(event: dict[str, Any]) -> None:
    EVENT_DIR.mkdir(parents=True, exist_ok=True)
    line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
    with event_lock:
        with EVENT_FILE.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")
            handle.flush()


def _blockchain_sync_placeholder(event: dict, trigger: str) -> None:
    """
    BLOCKCHAIN & SURICATA SYNC INTEGRATION POINT
    
    Calls suricata_rule_generator hooks for rule creation, Suricata reload,
    and Hyperledger Fabric synchronization.
    """
    try:
        if trigger == "ML_DETECTED_NEW_RULE" and handle_ml_detection:
            handle_ml_detection(event)
        elif trigger == "SURICATA_DETECTED" and handle_suricata_detection:
            handle_suricata_detection(event)
    except Exception as exc:
        print(f"[blockchain_sync] Error: {exc}", flush=True)


def empty_suricata_object() -> dict[str, Any]:
    return {
        "engine": None, "signature_id": None, "signature": None,
        "rule_creator": None, "severity": None, "alert_action": None,
        "flow_id": None
    }


def empty_ml_object() -> dict[str, Any]:
    return {
        "feature_source": None, "feature_schema": None,
        "binary_prediction": None, "random_forest_prediction": None,
        "xgboost_prediction": None, "ensemble_prediction": None,
        "ensemble_confidence": None, "models": [], "model_version": None
    }


def make_common_event(
    detection_source: str,
    attack_type: str | None,
    network: dict[str, Any],
    detection_timestamp: str,
    observer_node_id: str,
    attack_detected: bool = False,
    classification_status: str = "REQUIRES_REVIEW",
    classification_basis: str = "UNCLASSIFIED_DETECTION"
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "event_id": f"evt-{uuid.uuid4()}",
        "event_type": "INTRUSION_DETECTION",
        "timestamp": detection_timestamp,
        "organisation": {
            "organisation_id": ORG_ID,
            "organisation_name": ORG_NAME,
            "node_id": observer_node_id
        },
        "detection": {
            "detection_source": detection_source,
            "attack_detected": attack_detected,
            "classification_status": classification_status,
            "classification_basis": classification_basis,
            "attack_type": attack_type,
            "suricata": empty_suricata_object(),
            "machine_learning": empty_ml_object(),
            "rule_update": {
                "rule_generated": False,
                "rule_sid": None,
                "rule_content": None,
                "rule_creator": None,
                "rule_status": "NOT_REQUIRED" if detection_source == "SURICATA" else "PENDING"
            }
        },
        "network": network,
        "response": {
            "recommended_action": "REVIEW_AND_CONSIDER_BLOCK",
            "block_ip_addresses": [],
            "actual_block_status": "NOT_EXECUTED"
        },
        "evidence": {
            "sensor": observer_node_id,
            "detection_timestamp": detection_timestamp,
            "suricata_alert_id": None,
            "ml_prediction_id": None,
            "evidence_reference": None
        }
    }


def load_models() -> dict[str, Any]:
    model_dir = PROJECT_ROOT / "ml" / "models"
    loaded = {
        "binary_rf": joblib.load(model_dir / "binary" / "binary_random_forest.joblib"),
        "binary_xgb": XGBClassifier(),
        "multi_rf": joblib.load(model_dir / "multiclass" / "multiclass_random_forest.joblib"),
        "multi_xgb": XGBClassifier(),
        "multi_encoder": joblib.load(
            model_dir / "multiclass" / "multiclass_xgboost_label_encoder.joblib"
        )
    }
    loaded["binary_xgb"].load_model(str(model_dir / "binary" / "binary_xgboost.json"))
    loaded["multi_xgb"].load_model(str(model_dir / "multiclass" / "multiclass_xgboost.json"))

    for key in ("binary_rf", "binary_xgb", "multi_rf", "multi_xgb"):
        names = list(getattr(loaded[key], "feature_names_in_", []))
        if names and names != FEATURES:
            raise RuntimeError(f"{key} feature order mismatch: {names}")

    rf_classes = list(loaded["binary_rf"].classes_)
    xgb_classes = list(loaded["binary_xgb"].classes_)
    if "Attack" not in rf_classes:
        raise RuntimeError(f"Binary RF has no Attack class: {rf_classes}")
    if 1 not in xgb_classes:
        raise RuntimeError(f"Binary XGBoost has no encoded Attack class 1: {xgb_classes}")

    loaded["binary_rf_attack_idx"] = rf_classes.index("Attack")
    loaded["binary_xgb_attack_idx"] = xgb_classes.index(1)
    return loaded


MODELS = load_models()


def feature_row(flow: dict[str, Any]) -> pd.DataFrame:
    mapping = {
        "Destination Port": flow["dst_port"],
        # Python CICFlowMeter emits seconds; the training schema uses microseconds.
        # This conversion does not establish equivalence of the other features.
        "Flow Duration": float(flow["flow_duration"]) * 1_000_000.0,
        "Total Fwd Packets": flow["tot_fwd_pkts"],
        "Total Backward Packets": flow["tot_bwd_pkts"],
        "Total Length of Fwd Packets": flow["totlen_fwd_pkts"],
        "Total Length of Bwd Packets": flow["totlen_bwd_pkts"],
        "Flow Bytes/s": flow["flow_byts_s"],
        "Flow Packets/s": flow["flow_pkts_s"],
        "Fwd Packets/s": flow["fwd_pkts_s"],
        "Bwd Packets/s": flow["bwd_pkts_s"],
        "Down/Up Ratio": flow["down_up_ratio"]
    }
    values = {name: float(mapping[name]) for name in FEATURES}
    arr = np.asarray(list(values.values()), dtype=float)
    if not np.isfinite(arr).all():
        raise ValueError("Non-finite model feature")
    if any(value < 0 for value in values.values()):
        raise ValueError("Negative model feature")
    values["Destination Port"] = int(values["Destination Port"])
    return pd.DataFrame([[values[name] for name in FEATURES]], columns=FEATURES)


def score_flow(flow: dict[str, Any]) -> dict[str, Any]:
    row = feature_row(flow)
    rf_p = float(MODELS["binary_rf"].predict_proba(row)[0][MODELS["binary_rf_attack_idx"]])
    xgb_p = float(MODELS["binary_xgb"].predict_proba(row)[0][MODELS["binary_xgb_attack_idx"]])
    ensemble_p = (rf_p + xgb_p) / 2.0
    binary_prediction = "Attack" if ensemble_p >= 0.5 else "Normal"

    multi_rf = str(MODELS["multi_rf"].predict(row)[0])
    multi_xgb_index = int(MODELS["multi_xgb"].predict(row).reshape(-1)[0])
    multi_xgb = str(MODELS["multi_encoder"].inverse_transform([multi_xgb_index])[0])

    return {
        "binary_prediction": binary_prediction,
        "ensemble_probability": float(ensemble_p),
        "random_forest_attack_probability": rf_p,
        "xgboost_attack_probability": xgb_p,
        "random_forest_prediction": multi_rf,
        "xgboost_prediction": multi_xgb
    }


def clean_alert_cache(now: float) -> None:
    for key in [k for k, v in alerts.items() if now - v["received"] > ALERT_CACHE_SECONDS]:
        alerts.pop(key, None)
    for key in [k for k, v in seen_alerts.items() if now - v > ALERT_CACHE_SECONDS]:
        seen_alerts.pop(key, None)


def find_alert(
    flow: dict[str, Any], observer_node_id: str
) -> dict[str, Any] | None:
    keys = tuple(
        (observer_node_id, *key)
        for key in tuple_keys(
            flow.get("src_ip"), flow.get("dst_ip"),
            flow.get("src_port"), flow.get("dst_port"),
            flow.get("protocol", flow.get("proto"))
        )
    )
    now = time.time()
    with alert_lock:
        clean_alert_cache(now)
        for key in keys:
            item = alerts.get(key)
            if item:
                return item["event"]
    return None


def make_suricata_event(data: dict[str, Any], observer_node_id: str) -> dict[str, Any]:
    alert = data.get("alert") or {}
    timestamp = data.get("timestamp") or utcnow()
    network = {
        "source_ip": data.get("src_ip"),
        "source_port": data.get("src_port"),
        "destination_ip": data.get("dest_ip"),
        "destination_port": data.get("dest_port"),
        "protocol": normalise_protocol(data.get("proto")).upper()
    }
    signature = str(alert.get("signature") or "")
    attack_type = alert.get("category") or signature or "SURICATA_ALERT"
    is_informational = (
        signature.upper().startswith("ET INFO")
        or "GENERIC PROTOCOL" in attack_type.upper()
        or "GENERIC PROTOCOL" in signature.upper()
    )

    event = make_common_event(
        "SURICATA", str(attack_type), network, timestamp, observer_node_id,
        attack_detected=not is_informational,
        classification_status="INFORMATIONAL" if is_informational else "REQUIRES_REVIEW",
        classification_basis=(
            "SURICATA_SIGNATURE_PREFIX_ET_INFO"
            if is_informational else "UNCLASSIFIED_SURICATA_ALERT"
        )
    )
    event["detection"]["suricata"] = {
        "engine": os.environ.get("SURICATA_VERSION", "Suricata 8.0.7"),
        "signature_id": alert.get("signature_id"),
        "signature": alert.get("signature"),
        # Suricata EVE does not normally identify the rule author.
        "rule_creator": None,
        "severity": alert.get("severity"),
        "alert_action": alert.get("action"),
        "flow_id": str(data["flow_id"]) if data.get("flow_id") is not None else None
    }
    event["evidence"]["suricata_alert_id"] = (
        str(data["alert_id"]) if data.get("alert_id") is not None else None
    )
    event["evidence"]["evidence_reference"] = (
        f"suricata-flow:{data.get('flow_id')}" if data.get("flow_id") is not None else None
    )
    return event


def cache_suricata_alert(data: dict[str, Any], event: dict[str, Any], observer_node_id: str) -> bool:
    alert = data.get("alert") or {}
    dedup_key = (
        observer_node_id, str(data.get("flow_id") or ""), str(alert.get("signature_id") or ""),
        str(data.get("src_ip") or ""), str(data.get("dest_ip") or ""),
        int(data.get("src_port") or 0), int(data.get("dest_port") or 0),
        normalise_protocol(data.get("proto"))
    )
    keys = tuple(
        (observer_node_id, *key)
        for key in tuple_keys(
            data.get("src_ip"), data.get("dest_ip"),
            data.get("src_port"), data.get("dest_port"), data.get("proto")
        )
    )
    now = time.time()
    with alert_lock:
        clean_alert_cache(now)
        if dedup_key in seen_alerts:
            return False
        seen_alerts[dedup_key] = now
        for key in keys:
            alerts[key] = {"received": now, "event": event}
    return True


def handle_suricata(
    data: dict[str, Any], observer_node_id: str
) -> dict[str, Any]:
    _update_node_heartbeat(observer_node_id)
    if data.get("event_type") != "alert":
        return {"status": "ignored_non_alert_event"}
    event = make_suricata_event(data, observer_node_id)
    # Tag event with node approval status
    with _node_lock:
        node_entry = _node_registry.get(observer_node_id, {})
        node_approval = node_entry.get("approval_status", "APPROVED")
    if node_approval in ("PENDING_APPROVAL", "REJECTED"):
        event["node_approval_status"] = "PENDING"
    if not cache_suricata_alert(data, event, observer_node_id):
        return {"status": "duplicate_alert_ignored", "event_id": event["event_id"]}
    append_event(event)
    _blockchain_sync_placeholder(event, "SURICATA_DETECTED")
    return {"status": "suricata_event_written", "event_id": event["event_id"]}


def handle_flow(flow: dict[str, Any], observer_node_id: str) -> dict[str, Any]:
    _update_node_heartbeat(observer_node_id)
    # Only yield precedence if Suricata matched a confirmed signature attack.
    # Generic protocol decodes or informational notices must not suppress ML attack detection.
    correlated = find_alert(flow, observer_node_id)
    if correlated:
        is_attack = correlated.get("detection", {}).get("attack_detected", False)
        sig = str(correlated.get("detection", {}).get("suricata", {}).get("signature", "")).lower()
        cat = str(correlated.get("detection", {}).get("attack_type", "")).lower()
        is_generic = "generic protocol" in cat or "generic protocol" in sig or "et info" in sig
        if is_attack and not is_generic:
            return {"status": "suricata_precedence", "event_id": correlated["event_id"]}

    result = score_flow(flow)
    if result["binary_prediction"] == "Normal":
        return {"status": "benign_no_event", "prediction": "Normal"}

    timestamp = flow.get("timestamp") or utcnow()
    network = {
        "source_ip": flow.get("src_ip"),
        "source_port": flow.get("src_port"),
        "destination_ip": flow.get("dst_ip", flow.get("dest_ip")),
        "destination_port": flow.get("dst_port", flow.get("dest_port")),
        "protocol": normalise_protocol(flow.get("protocol", flow.get("proto"))).upper()
    }

    # Determine the best attack category label.
    # If the multiclass RF says "Normal" (contradicting the binary Attack prediction),
    # fall back to the XGBoost multiclass prediction; if that also says "Normal",
    # label as "Unknown Attack" so the event is never shown as benign.
    multi_rf_label   = result["random_forest_prediction"]
    multi_xgb_label  = result["xgboost_prediction"]
    if multi_rf_label == "Normal":
        attack_category = multi_xgb_label if multi_xgb_label != "Normal" else "Unknown Attack"
    else:
        attack_category = multi_rf_label

    event = make_common_event(
        "ML_MODEL", attack_category, network,
        timestamp, observer_node_id,
        attack_detected=True,
        classification_status="MODEL_PREDICTED",
        classification_basis="ML_BINARY_ENSEMBLE"
    )
    prediction_id = f"ml-pred-{uuid.uuid4()}"
    event["detection"]["machine_learning"] = {
        "feature_source": "CICFlowMeter",
        "feature_schema": "CICIDS2017_V2_11_FEATURES",
        "binary_prediction": result["binary_prediction"],
        "random_forest_prediction": result["random_forest_prediction"],
        "xgboost_prediction": result["xgboost_prediction"],
        "ensemble_prediction": result["binary_prediction"],
        # Raw ensemble attack probability; not a calibrated confidence score.
        "ensemble_confidence": result["ensemble_probability"],
        "models": ["Random Forest", "XGBoost"],
        "model_version": MODEL_VERSION
    }
    event["evidence"]["ml_prediction_id"] = prediction_id
    event["evidence"]["evidence_reference"] = (
        f"cicflowmeter-flow:{flow.get('flow_id')}"
        if flow.get("flow_id") is not None else None
    )

    # ── Auto-generate Suricata Rule from ML Attack Pattern ────────────────
    generated_rule_str = None
    if generate_rule:
        try:
            generated_rule_str = generate_rule(event)
            if generated_rule_str:
                import re
                sid_match = re.search(r"sid:(\d+);", generated_rule_str)
                sid_num = int(sid_match.group(1)) if sid_match else 9000001
                event["detection"]["rule_update"] = {
                    "rule_generated": True,
                    "rule_sid": sid_num,
                    "rule_content": generated_rule_str,
                    "rule_creator": "ML_AUTO_GENERATOR",
                    "rule_status": "GENERATED_PENDING_BLOCKCHAIN_SYNC"
                }
        except Exception as exc:
            print(f"[rule_generator] Error: {exc}", flush=True)

    append_event(event)
    _blockchain_sync_placeholder(event, "ML_DETECTED_NEW_RULE")

    return {
        "status": "attack_event_written",
        "event_id": event["event_id"],
        "ml_prediction_id": prediction_id,
        "rule_generated": bool(generated_rule_str),
        "rule": generated_rule_str,
        "feature_compatibility": FEATURE_COMPATIBILITY,
        "warning": (
            "ML output is experimental until live CICFlowMeter features "
            "are verified against the training feature definitions."
        )
    }


class Handler(BaseHTTPRequestHandler):
    def reply(self, status_code: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _parse_query(self) -> dict[str, str]:
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        return {k: v[0] for k, v in qs.items()}

    def _path_base(self) -> str:
        return urlparse(self.path).path

    def do_GET(self) -> None:
        path = self._path_base()
        qs = self._parse_query()

        if path == "/health":
            self.reply(200, {
                "status": "ok",
                "models_loaded": True,
                "feature_compatibility": FEATURE_COMPATIBILITY,
                "service_role": "CENTRAL_ML_API",
                "node_authentication": (
                    "CONFIGURED"
                    if set(NODE_TOKEN_HASHES) == {"NODE_A", "NODE_B", "NODE_C"}
                    else "INCOMPLETE"
                ),
                "event_file": str(EVENT_FILE)
            })
            return

        if path == "/api/health":
            self.reply(200, {
                "status": "ok",
                "timestamp": utcnow(),
                "models_loaded": True,
                "feature_compatibility": FEATURE_COMPATIBILITY,
                "event_file": str(EVENT_FILE),
                "event_file_exists": EVENT_FILE.is_file(),
                "blockchain_status": "PENDING_NOT_SUBMITTED"
            })
            return

        if path == "/api/stats":
            self.reply(200, _build_stats())
            return

        if path == "/api/events":
            try:
                page = max(1, int(qs.get("page", "1")))
                page_size = min(200, max(1, int(qs.get("page_size", "50"))))
            except ValueError:
                self.reply(400, {"error": "invalid_pagination_params"})
                return
            detection_method = qs.get("detection_method", "")
            self.reply(200, _read_events_page(page, page_size, detection_method))
            return

        if path == "/api/nodes":
            with _node_lock:
                node_list = list(_node_registry.values())
            pending = [n for n in node_list if n.get("approval_status") == "PENDING_APPROVAL"]
            self.reply(200, {
                "nodes": node_list,
                "total": len(node_list),
                "pending_approvals": len(pending)
            })
            return

        if path == "/api/blocked":
            blocked = get_blocked_ips()
            self.reply(200, {"blocked_ips": blocked, "total": len(blocked)})
            return

        if path == "/api/rules":
            rules = []
            if EVENT_FILE.is_file():
                try:
                    raw_lines = EVENT_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
                    for line in reversed(raw_lines):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            evt = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        ru = evt.get("detection", {}).get("rule_update", {})
                        if ru.get("rule_generated"):
                            rules.append({
                                "event_id": evt.get("event_id"),
                                "timestamp": evt.get("timestamp"),
                                "attack_type": evt.get("detection", {}).get("attack_type"),
                                "source_ip": evt.get("network", {}).get("source_ip"),
                                "destination_port": evt.get("network", {}).get("destination_port"),
                                "protocol": evt.get("network", {}).get("protocol"),
                                "rule_sid": ru.get("rule_sid"),
                                "rule_content": ru.get("rule_content"),
                                "rule_status": ru.get("rule_status"),
                                "rule_creator": ru.get("rule_creator")
                            })
                except Exception as exc:
                    print(f"[api/rules] Error reading events: {exc}", flush=True)
            self.reply(200, {"rules": rules, "total": len(rules)})
            return

        self.reply(404, {"error": "not_found"})

    def _read_body(self) -> dict[str, Any] | None:
        """Read and parse JSON body. Returns None and sends error reply on failure."""
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_REQUEST_BYTES:
                self.reply(400, {"error": "invalid_content_length"})
                return None
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                self.reply(400, {"error": "JSON_body_must_be_an_object"})
                return None
            return data
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            self.reply(400, {"error": f"invalid_json: {exc}"})
            return None

    def do_POST(self) -> None:
        path = self._path_base()

        # ── Admin actions (no node token needed) ─────────────────────────────
        if path == "/api/block":
            data = self._read_body()
            if data is None:
                return
            ip = str(data.get("ip", "")).strip()
            if not ip:
                self.reply(400, {"error": "ip_required"})
                return
            reason = str(data.get("reason", "Manually blocked"))
            duration = int(data.get("duration_minutes", 0))
            entry = block_ip(ip, reason, duration)
            self.reply(200, {"status": "blocked", **entry})
            return

        if path == "/api/unblock":
            data = self._read_body()
            if data is None:
                return
            ip = str(data.get("ip", "")).strip()
            if not ip:
                self.reply(400, {"error": "ip_required"})
                return
            removed = unblock_ip(ip)
            self.reply(200, {"status": "unblocked" if removed else "not_blocked", "ip": ip})
            return

        if path == "/api/nodes/approve":
            data = self._read_body()
            if data is None:
                return
            node_id = str(data.get("node_id", "")).strip()
            approved_by = str(data.get("approved_by", "ADMIN")).strip() or "ADMIN"
            if not node_id:
                self.reply(400, {"error": "node_id_required"})
                return
            with _node_lock:
                entry = _node_registry.get(node_id)
                if not entry:
                    self.reply(404, {"error": "node_not_found"})
                    return
                if entry.get("approval_status") == "APPROVED":
                    self.reply(200, {"status": "already_approved", "node_id": node_id})
                    return
                received = entry.setdefault("received_approvals", [])
                if approved_by not in received:
                    received.append(approved_by)
                required = entry.get("required_approvals", 1)
                if len(received) >= required:
                    entry["approval_status"] = "APPROVED"
                    status = "approved"
                else:
                    status = "pending_more_approvals"
            self.reply(200, {
                "status": status, "node_id": node_id,
                "received": len(received), "required": required
            })
            return

        if path == "/api/nodes/reject":
            data = self._read_body()
            if data is None:
                return
            node_id = str(data.get("node_id", "")).strip()
            if not node_id:
                self.reply(400, {"error": "node_id_required"})
                return
            with _node_lock:
                entry = _node_registry.get(node_id)
                if not entry:
                    self.reply(404, {"error": "node_not_found"})
                    return
                entry["approval_status"] = "REJECTED"
            self.reply(200, {"status": "rejected", "node_id": node_id})
            return

        if path == "/api/events/clear":
            try:
                count = 0
                with event_lock:
                    if EVENT_FILE.is_file():
                        lines = EVENT_FILE.read_text(encoding="utf-8").splitlines()
                        count = sum(1 for l in lines if l.strip())
                        EVENT_FILE.write_text("", encoding="utf-8")
                self.reply(200, {"status": "cleared", "events_removed": count})
            except Exception as exc:
                self.reply(500, {"error": f"clear_failed: {exc}"})
            return

        # ── Node-authenticated endpoints ──────────────────────────────────────
        if path not in {"/flow", "/suricata"}:
            self.reply(404, {"error": "not_found"})
            return

        if set(NODE_TOKEN_HASHES) != {"NODE_A", "NODE_B", "NODE_C"}:
            self.reply(503, {"error": "all_three_node_credentials_required"})
            return

        observer_node_id = authenticate_node(self.headers.get("Authorization", ""))
        if observer_node_id is None:
            self.reply(401, {"error": "unauthorized"})
            return

        try:
            data = self._read_body()
            if data is None:
                return
            if path == "/flow":
                self.reply(200, handle_flow(data, observer_node_id))
                return
            if path == "/suricata":
                self.reply(200, handle_suricata(data, observer_node_id))
                return
        except KeyError as exc:
            self.reply(400, {"error": f"missing_flow_field: {exc}"})
        except (TypeError, ValueError) as exc:
            self.reply(400, {"error": str(exc)})
        except Exception as exc:
            self.reply(500, {"error": f"internal_error: {exc}"})

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"{self.address_string()} - {fmt % args}", flush=True)


if __name__ == "__main__":
    print(f"Starting IPS ML API on {HOST}:{PORT}", flush=True)
    print(f"Project root: {PROJECT_ROOT}", flush=True)
    print(f"Event JSONL: {EVENT_FILE}", flush=True)
    print(
        "WARNING: CICFlowMeter feature compatibility is NOT VERIFIED; "
        "firewall blocking is not implemented.",
        flush=True
    )
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping IPS ML API...", flush=True)
    finally:
        server.server_close()
