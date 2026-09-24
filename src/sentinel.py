#!/usr/bin/env python3
"""Sentinel: BOINC, service/process or Docker health checks with Telegram alerts."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import http.client
import json
import logging
import math
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Optional


SCHEMA_VERSION = 3
KST = timezone(timedelta(hours=9), name="KST")
LOGGER = logging.getLogger("sentinel")
EXECUTING_RE = re.compile(r"^\s*active_task_state\s*:\s*EXECUTING\s*$", re.MULTILINE)

MONITORS = ("boinc", "process", "docker")
BOINC_TARGET = "boinc"
TARGET_KINDS = ("service", "process", "cmdline", "container")
MONITOR_KINDS = {"process": ("service", "process", "cmdline"), "docker": ("container",)}
# Kinds whose restart marker is a counter of supervisor restarts.
COUNTER_KINDS = ("service", "container")
CONFIG_FILE = Path("/etc/sentinel/sentinel.conf")
CONFIG_LINE_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
CONTAINER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
UNIT_NAME_RE = re.compile(r"^[A-Za-z0-9:_.@\\-]+$")
OTHER_UNIT_TYPES = {
    "automount",
    "device",
    "mount",
    "path",
    "scope",
    "slice",
    "socket",
    "swap",
    "target",
    "timer",
}
# /proc/<pid>/comm holds at most TASK_COMM_LEN - 1 bytes.
COMM_LENGTH = 15
COUNTER_KEYS = ("checks", "failures", "incidents", "restarts")
HEALTH_ORDER = ("healthy", "unknown", "degraded", "unhealthy")


class StateError(RuntimeError):
    """Base class for state handling failures."""


class FutureSchemaError(StateError):
    """Raised when a state file was written by a newer Sentinel version."""


class InvalidStateError(StateError):
    """Raised when a state file has invalid JSON or structure."""


class StateLockedError(StateError):
    """Raised when another Sentinel process holds the state lock."""


class ConfigError(ValueError):
    """Raised when settings or the targets file are invalid."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_utc(value: Optional[str]) -> Optional[datetime]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidStateError("timestamp is not a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidStateError(f"invalid timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise InvalidStateError("timestamp is missing a timezone")
    return parsed.astimezone(timezone.utc)


def required_utc(value: Any, field_name: str) -> datetime:
    parsed = parse_utc(value)
    if parsed is None:
        raise InvalidStateError(f"{field_name} is missing")
    return parsed


def week_key(value: datetime) -> str:
    local = value.astimezone(KST)
    year, week, _ = local.isocalendar()
    return f"{year}-W{week:02d}"


def weekly_due(value: datetime) -> datetime:
    local = value.astimezone(KST)
    monday = (local - timedelta(days=local.weekday())).replace(
        hour=9, minute=0, second=0, microsecond=0
    )
    return monday.astimezone(timezone.utc)


def _env_flag(environ: dict[str, str], name: str, default: str) -> bool:
    return environ.get(name, default).strip().lower() not in {"", "0", "false", "no", "off"}


def read_config_file(path: Path) -> dict[str, str]:
    """Parse the KEY=VALUE subset of a systemd EnvironmentFile.

    systemd hands sentinel.conf to the unit through EnvironmentFile=. A shell
    (`sudo sentinel check-config`) does not, so the file is read here too;
    real environment variables still win, exactly as they do under systemd.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"config file unreadable: {path}: {type(exc).__name__}") from exc
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        match = CONFIG_LINE_RE.match(line)
        if match is None:
            continue
        key, value = match.group(1), match.group(2).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value
    return values


def normalize_monitor(value: str) -> str:
    """Canonicalize SENTINEL_MONITOR, which may combine monitors: "process, boinc".

    Known monitors are deduplicated and put in MONITORS order so the stored
    state and install.sh compare equal however the list was written. Unknown
    names are kept for validation to reject.
    """
    parts: list[str] = []
    for part in value.split(","):
        part = part.strip().lower()
        if part and part not in parts:
            parts.append(part)
    if not parts:
        return "boinc"
    known = sorted((part for part in parts if part in MONITORS), key=MONITORS.index)
    return ",".join(known + [part for part in parts if part not in MONITORS])


def monitor_parts(monitor: str) -> tuple[str, ...]:
    return tuple(monitor.split(","))


def _valid_monitor(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and all(part in MONITORS for part in monitor_parts(value))
        and normalize_monitor(value) == value
    )


def read_boot_id(path: Path = Path("/proc/sys/kernel/random/boot_id")) -> str:
    return path.read_text(encoding="ascii").strip()


def target_kind(target_id: str) -> str:
    if target_id == BOINC_TARGET:
        return BOINC_TARGET
    return target_id.partition(":")[0]


def _counter_block(key: str) -> dict[str, Any]:
    return {"week": key, "checks": 0, "failures": 0, "incidents": 0, "restarts": 0}


def default_target_state() -> dict[str, Any]:
    return {
        "health": "unknown",
        "consecutive_failures": 0,
        "incident_started_at": None,
        "incident_confirmed": False,
        "incident_alert_sent": False,
        "last_alert_at": None,
        "last_check": None,
        "pending_recovery": None,
        "pending_recovery_alert": None,
        "last_recovery_at": None,
        "recoveries_this_incident": 0,
        "restart_marker": None,
        "pending_restart": None,
        "last_restart_alert_at": None,
    }


def default_state(boot_id: str, now: datetime, monitor: str = "boinc") -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "monitor": monitor,
        "boot_id": boot_id,
        "targets": {},
        "pending_state_reset_alert": None,
        "pending_boot_alert": None,
        "current_week": _counter_block(week_key(now)),
        "pending_weekly": None,
    }


def _is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_optional_str(value: Any) -> bool:
    return value is None or isinstance(value, str)


def _validate_counter(value: Any, pending: bool = False) -> None:
    if not isinstance(value, dict):
        raise InvalidStateError("weekly counter is not an object")
    keys = ("start_week", "end_week") if pending else ("week",)
    for key in keys:
        if not isinstance(value.get(key), str) or not value[key]:
            raise InvalidStateError(f"weekly counter has invalid {key}")
    for key in COUNTER_KEYS:
        if not _is_nonnegative_int(value.get(key)):
            raise InvalidStateError(f"weekly counter has invalid {key}")
    if pending:
        required_utc(value.get("due_at"), "pending_weekly.due_at")


def _validate_target_id(target_id: Any) -> None:
    if target_id == BOINC_TARGET:
        return
    if not isinstance(target_id, str):
        raise InvalidStateError("target ID is not a string")
    kind, separator, value = target_id.partition(":")
    if not separator or kind not in TARGET_KINDS or not value:
        raise InvalidStateError(f"target ID is invalid: {target_id!r}")


def _validate_details(target_id: str, details: Any) -> None:
    if not isinstance(details, dict):
        raise InvalidStateError(f"{target_id} last_check.details is invalid")
    kind = target_kind(target_id)
    if kind == BOINC_TARGET:
        if not isinstance(details.get("service_active"), bool):
            raise InvalidStateError("last_check.service_active is invalid")
        if not _is_nonnegative_int(details.get("executing_tasks")):
            raise InvalidStateError("last_check.executing_tasks is invalid")
        cpu_percent = details.get("cpu_percent")
        if (
            not isinstance(cpu_percent, (int, float))
            or isinstance(cpu_percent, bool)
            or not math.isfinite(cpu_percent)
            or cpu_percent < 0
        ):
            raise InvalidStateError("last_check.cpu_percent is invalid")
    elif kind == "service":
        for key in ("load_state", "active_state", "sub_state"):
            if not _is_optional_str(details.get(key)):
                raise InvalidStateError(f"{target_id} last_check.{key} is invalid")
        for key in ("main_pid", "n_restarts"):
            value = details.get(key)
            if value is not None and not _is_nonnegative_int(value):
                raise InvalidStateError(f"{target_id} last_check.{key} is invalid")
    elif kind == "container":
        for key in ("status", "health"):
            if not _is_optional_str(details.get(key)):
                raise InvalidStateError(f"{target_id} last_check.{key} is invalid")
        for key in ("restart_count", "exit_code"):
            value = details.get(key)
            if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
                raise InvalidStateError(f"{target_id} last_check.{key} is invalid")
    elif not _is_nonnegative_int(details.get("count")):
        raise InvalidStateError(f"{target_id} last_check.count is invalid")


def _validate_target(target_id: str, target: Any) -> None:
    if not isinstance(target, dict):
        raise InvalidStateError(f"target {target_id} is not an object")
    missing = set(default_target_state()).difference(target)
    if missing:
        raise InvalidStateError(
            f"target {target_id} is missing keys: {', '.join(sorted(missing))}"
        )
    if target["health"] not in HEALTH_ORDER:
        raise InvalidStateError("health is invalid")
    for key in ("consecutive_failures", "recoveries_this_incident"):
        if not _is_nonnegative_int(target[key]):
            raise InvalidStateError(f"{key} is invalid")
    for key in ("incident_confirmed", "incident_alert_sent"):
        if not isinstance(target[key], bool):
            raise InvalidStateError(f"{key} is invalid")
    for key in ("incident_started_at", "last_alert_at", "last_recovery_at", "last_restart_alert_at"):
        parse_utc(target[key])
    if target["incident_confirmed"]:
        required_utc(target["incident_started_at"], "incident_started_at")
    if target["incident_alert_sent"]:
        if not target["incident_confirmed"]:
            raise InvalidStateError("an alert cannot exist without a confirmed incident")
        required_utc(target["last_alert_at"], "last_alert_at")
    if target["restart_marker"] is not None and not _is_nonnegative_int(target["restart_marker"]):
        raise InvalidStateError("restart_marker is invalid")

    check = target["last_check"]
    if check is not None:
        if not isinstance(check, dict):
            raise InvalidStateError("last_check is invalid")
        required_utc(check.get("checked_at"), "last_check.checked_at")
        if not isinstance(check.get("reasons"), list) or not all(
            isinstance(item, str) for item in check["reasons"]
        ):
            raise InvalidStateError("last_check.reasons is invalid")
        _validate_details(target_id, check.get("details"))

    recovery = target["pending_recovery"]
    if recovery is not None:
        if not isinstance(recovery, dict):
            raise InvalidStateError("pending_recovery is invalid")
        required_utc(recovery.get("started_at"), "pending_recovery.started_at")
        required_utc(recovery.get("recovered_at"), "pending_recovery.recovered_at")

    attempt = target["pending_recovery_alert"]
    if attempt is not None:
        if not isinstance(attempt, dict):
            raise InvalidStateError("pending_recovery_alert is invalid")
        required_utc(attempt.get("attempted_at"), "pending_recovery_alert.attempted_at")
        for key in ("attempt", "max_attempts"):
            if not _is_nonnegative_int(attempt.get(key)):
                raise InvalidStateError(f"pending_recovery_alert.{key} is invalid")
        if not isinstance(attempt.get("succeeded"), bool):
            raise InvalidStateError("pending_recovery_alert.succeeded is invalid")
        if not isinstance(attempt.get("detail"), str):
            raise InvalidStateError("pending_recovery_alert.detail is invalid")

    restart = target["pending_restart"]
    if restart is not None:
        if not isinstance(restart, dict):
            raise InvalidStateError("pending_restart is invalid")
        if not _is_nonnegative_int(restart.get("count")) or restart["count"] < 1:
            raise InvalidStateError("pending_restart.count is invalid")
        required_utc(restart.get("first_at"), "pending_restart.first_at")
        required_utc(restart.get("last_at"), "pending_restart.last_at")
        if not isinstance(restart.get("detail"), str):
            raise InvalidStateError("pending_restart.detail is invalid")


def validate_state(state: Any) -> dict[str, Any]:
    if not isinstance(state, dict):
        raise InvalidStateError("state root is not an object")
    required = {
        "schema_version",
        "monitor",
        "boot_id",
        "targets",
        "pending_state_reset_alert",
        "pending_boot_alert",
        "current_week",
        "pending_weekly",
    }
    missing = required.difference(state)
    if missing:
        raise InvalidStateError(f"state is missing keys: {', '.join(sorted(missing))}")
    if state["schema_version"] != SCHEMA_VERSION:
        raise InvalidStateError("state has the wrong schema after migration")
    if not _valid_monitor(state["monitor"]):
        raise InvalidStateError("monitor is invalid")
    if not isinstance(state["boot_id"], str):
        raise InvalidStateError("boot_id is invalid")
    if not isinstance(state["targets"], dict):
        raise InvalidStateError("targets is invalid")
    for target_id, target in state["targets"].items():
        _validate_target_id(target_id)
        _validate_target(target_id, target)
    reset = state["pending_state_reset_alert"]
    if reset is not None:
        if not isinstance(reset, dict):
            raise InvalidStateError("pending_state_reset_alert is invalid")
        required_utc(reset.get("detected_at"), "pending_state_reset_alert.detected_at")
        for key in ("backup_name", "error_type"):
            if not isinstance(reset.get(key), str) or not reset[key]:
                raise InvalidStateError(f"pending_state_reset_alert.{key} is invalid")
    boot = state["pending_boot_alert"]
    if boot is not None:
        if not isinstance(boot, dict):
            raise InvalidStateError("pending_boot_alert is invalid")
        required_utc(boot.get("detected_at"), "pending_boot_alert.detected_at")
    _validate_counter(state["current_week"])
    if state["pending_weekly"] is not None:
        _validate_counter(state["pending_weekly"], pending=True)
    return state


# Keys of the schema 1/2 flat layout, where the single BOINC incident lived at
# the state root. Schema 3 moves them under targets.boinc.
_FLAT_INCIDENT_KEYS = (
    "health",
    "consecutive_failures",
    "incident_started_at",
    "incident_confirmed",
    "incident_alert_sent",
    "last_alert_at",
    "last_check",
    "pending_recovery",
    "pending_recovery_alert",
    "last_recovery_at",
    "recoveries_this_incident",
)


def _flat_defaults(boot_id: str, now: datetime) -> dict[str, Any]:
    flat = {key: value for key, value in default_target_state().items() if key in _FLAT_INCIDENT_KEYS}
    flat.update(
        boot_id=boot_id,
        pending_state_reset_alert=None,
        current_week=_counter_block(week_key(now)),
        pending_weekly=None,
    )
    return flat


def _upgrade_schema0(raw: dict[str, Any], boot_id: str, now: datetime) -> dict[str, Any]:
    # Schema 0 was the pre-release flat-counter format. Preserve every compatible
    # field, while initializing notification bookkeeping introduced later.
    flat = _flat_defaults(str(raw.get("boot_id", boot_id)), now)
    for key in (
        "health",
        "consecutive_failures",
        "incident_started_at",
        "incident_confirmed",
        "incident_alert_sent",
        "last_alert_at",
        "last_check",
    ):
        if key in raw:
            flat[key] = raw[key]
    old_week = raw.get("current_week")
    if old_week is None and any(key in raw for key in ("week", "checks", "failures", "incidents")):
        old_week = {
            "week": raw.get("week", week_key(now)),
            "checks": raw.get("checks", 0),
            "failures": raw.get("failures", 0),
            "incidents": raw.get("incidents", 0),
        }
    if old_week is not None:
        flat["current_week"] = old_week
    return flat


def _upgrade_schema1(raw: dict[str, Any]) -> dict[str, Any]:
    # Schema 2 only added auto-recovery bookkeeping, so every schema 1 field
    # carries over untouched and the cooldown simply starts unarmed.
    flat = dict(raw)
    flat.setdefault("pending_recovery_alert", None)
    flat.setdefault("last_recovery_at", None)
    flat.setdefault("recoveries_this_incident", 0)
    return flat


def _upgrade_flat(flat: dict[str, Any]) -> dict[str, Any]:
    missing = {"boot_id", "current_week", "pending_weekly", "pending_state_reset_alert"}
    missing.update(_FLAT_INCIDENT_KEYS)
    missing.difference_update(flat)
    if missing:
        raise InvalidStateError(f"state is missing keys: {', '.join(sorted(missing))}")
    target = default_target_state()
    for key in _FLAT_INCIDENT_KEYS:
        target[key] = flat[key]
    check = flat["last_check"]
    if isinstance(check, dict) and "details" not in check:
        target["last_check"] = {
            "checked_at": check.get("checked_at"),
            "reasons": check.get("reasons"),
            "details": {
                key: check.get(key) for key in ("service_active", "executing_tasks", "cpu_percent")
            },
        }
    counters = []
    for counter in (flat["current_week"], flat["pending_weekly"]):
        if isinstance(counter, dict):
            counter = dict(counter)
            counter.setdefault("restarts", 0)
        counters.append(counter)
    return {
        "schema_version": SCHEMA_VERSION,
        "monitor": "boinc",
        "boot_id": flat["boot_id"],
        "targets": {BOINC_TARGET: target},
        "pending_state_reset_alert": flat["pending_state_reset_alert"],
        "pending_boot_alert": None,
        "current_week": counters[0],
        "pending_weekly": counters[1],
    }


def migrate_state(raw: Any, boot_id: str, now: datetime) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise InvalidStateError("state root is not an object")
    version = raw.get("schema_version", 0)
    if not isinstance(version, int) or isinstance(version, bool) or version < 0:
        raise InvalidStateError("schema_version is invalid")
    if version > SCHEMA_VERSION:
        raise FutureSchemaError(
            f"state schema {version} is newer than supported schema {SCHEMA_VERSION}"
        )
    if version == SCHEMA_VERSION:
        # pending_boot_alert arrived after the first schema 3 build.
        raw.setdefault("pending_boot_alert", None)
        return validate_state(raw)
    if version == 0:
        flat = _upgrade_schema0(raw, boot_id, now)
    elif version == 1:
        flat = _upgrade_schema1(raw)
    else:
        flat = raw
    # Schema 3 nests the single BOINC incident under targets.boinc so that
    # the process monitor can keep one independent incident per target.
    return validate_state(_upgrade_flat(flat))


class StateStore:
    def __init__(self, path: Path):
        self.path = path

    def _ensure_directory(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self.path.parent, 0o700)
        except PermissionError:
            pass

    @contextlib.contextmanager
    def lock(
        self,
        timeout: float = 60.0,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        """Serialize every read-modify-write of the state file.

        systemd never runs the oneshot unit twice at once, but a manual
        `sentinel check` or `reset-state` can overlap a timer run.
        """
        self._ensure_directory()
        lock_path = self.path.with_name(f"{self.path.name}.lock")
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            deadline = monotonic() + timeout
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if monotonic() >= deadline:
                        raise StateLockedError(
                            f"{lock_path} is held by another sentinel process"
                        ) from None
                    sleeper(0.5)
            yield
        finally:
            os.close(descriptor)

    def _backup_name(self, label: str, now: datetime) -> Path:
        stamp = now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        return self.path.with_name(f"{self.path.name}.{label}-{stamp}")

    def _sync_directory(self) -> None:
        descriptor = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def load(
        self, boot_id: str, now: datetime, monitor: str = "boinc"
    ) -> tuple[dict[str, Any], Optional[Path]]:
        self._ensure_directory()
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                raw = json.load(handle)
            state = migrate_state(raw, boot_id, now)
            if raw.get("schema_version", 0) != SCHEMA_VERSION:
                self.save(state)
                LOGGER.info("state migrated schema=%s", SCHEMA_VERSION)
            return state, None
        except FileNotFoundError:
            state = default_state(boot_id, now, monitor)
            self.save(state)
            LOGGER.info("state initialized")
            return state, None
        except FutureSchemaError:
            raise
        except (json.JSONDecodeError, UnicodeDecodeError, InvalidStateError) as exc:
            backup = self._backup_name("corrupt", now)
            os.replace(self.path, backup)
            self._sync_directory()
            state = default_state(boot_id, now, monitor)
            state["pending_state_reset_alert"] = {
                "detected_at": utc_text(now),
                "backup_name": backup.name,
                "error_type": type(exc).__name__,
            }
            self.save(state)
            LOGGER.error("corrupt state preserved backup=%s error=%s", backup.name, type(exc).__name__)
            return state, backup

    def save(self, state: dict[str, Any]) -> None:
        validate_state(state)
        self._ensure_directory()
        descriptor, temp_name = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        try:
            os.fchmod(descriptor, 0o600)
            if os.geteuid() == 0:
                os.fchown(descriptor, 0, 0)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                descriptor = -1
                json.dump(
                    state,
                    handle,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.path)
            self._sync_directory()
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass

    def reset(self, boot_id: str, now: datetime, monitor: str = "boinc") -> Optional[Path]:
        self._ensure_directory()
        backup = None
        if self.path.exists():
            backup = self._backup_name("reset", now)
            os.replace(self.path, backup)
            self._sync_directory()
        self.save(default_state(boot_id, now, monitor))
        return backup


@dataclass
class CheckResult:
    service_active: bool
    executing_tasks: int
    cpu_percent: float
    errors: list[str] = field(default_factory=list)

    def reasons(self, threshold: float) -> list[str]:
        reasons = list(self.errors)
        if not self.service_active:
            reasons.append("service inactive")
        if self.executing_tasks < 1:
            reasons.append("no EXECUTING task")
        if self.cpu_percent < threshold:
            reasons.append(f"CPU {self.cpu_percent:.1f}% < {threshold:.1f}%")
        return reasons

    def healthy(self, threshold: float) -> bool:
        return not self.reasons(threshold)

    def starved(self) -> bool:
        """True when BOINC is alive and measurable but has no task to run.

        This is the only failure signature an account manager sync can fix. A
        dead service needs a restart and a probe error means the measurement
        itself is untrustworthy, so both must not trigger recovery.
        """
        return self.service_active and not self.errors and self.executing_tasks == 0


@dataclass
class TargetResult:
    """One target's observation, the unit every monitor reports in."""

    target_id: str
    reasons: list[str]
    details: dict[str, Any]
    # Compared against the previous check to detect restarts. None means the
    # target has nothing to compare right now (for example it is down).
    restart_marker: Optional[int] = None
    # What is compared with the stored marker, when that differs from the
    # marker stored for next time. None means restart_marker itself.
    restart_compare: Optional[int] = None
    # False when the query itself failed; the stored marker is then kept.
    probe_ok: bool = True
    # None when the recovery action fits this failure, otherwise why not.
    recovery_hint: Optional[str] = "no recovery action"

    @property
    def healthy(self) -> bool:
        return not self.reasons


@dataclass
class Settings:
    monitor: str = "boinc"
    state_file: Path = Path("/var/lib/sentinel/state.json")
    service_name: str = "boinc-client.service"
    boinccmd: str = "/usr/bin/boinccmd"
    boinc_data_dir: Path = Path("/var/lib/boinc-client")
    cgroup_root: Path = Path("/sys/fs/cgroup")
    sample_seconds: float = 10.0
    total_vcpus: float = 2.0
    cpu_threshold: float = 30.0
    targets_file: Path = Path("/etc/sentinel/targets")
    proc_root: Path = Path("/proc")
    systemctl: str = "/usr/bin/systemctl"
    docker_socket: Path = Path("/var/run/docker.sock")
    alert_after_failures: int = 2
    reminder_hours: float = 12.0
    telegram_chat_id: str = ""
    telegram_token_file: Optional[Path] = None
    command_timeout: float = 8.0
    recover_enabled: bool = True
    recover_after_failures: int = 1
    recover_cooldown_hours: float = 6.0
    recover_max_per_incident: int = 2
    recover_timeout: float = 45.0

    @classmethod
    def from_environment(cls, environ: Optional[dict[str, str]] = None) -> "Settings":
        if environ is None:
            environ = dict(os.environ)
        config_file = Path(environ.get("SENTINEL_CONFIG", str(CONFIG_FILE)))
        merged = read_config_file(config_file)
        merged.update(environ)
        return cls._from_mapping(merged)

    @classmethod
    def _from_mapping(cls, environ: dict[str, str]) -> "Settings":
        credential_dir = environ.get("CREDENTIALS_DIRECTORY")
        token_file = (
            Path(credential_dir) / "telegram-token"
            if credential_dir
            else Path("/etc/sentinel/telegram-token")
        )
        try:
            return cls(
                monitor=normalize_monitor(environ.get("SENTINEL_MONITOR", "boinc")),
                state_file=Path(environ.get("STATE_FILE", "/var/lib/sentinel/state.json")),
                service_name=environ.get("BOINC_SERVICE", "boinc-client.service"),
                boinccmd=environ.get("BOINCCMD", "/usr/bin/boinccmd"),
                boinc_data_dir=Path(environ.get("BOINC_DATA_DIR", "/var/lib/boinc-client")),
                cgroup_root=Path(environ.get("CGROUP_ROOT", "/sys/fs/cgroup")),
                sample_seconds=float(environ.get("SAMPLE_SECONDS", "10")),
                total_vcpus=float(environ.get("TOTAL_VCPUS", "2")),
                cpu_threshold=float(environ.get("CPU_THRESHOLD", "30")),
                targets_file=Path(environ.get("TARGETS_FILE", "/etc/sentinel/targets")),
                docker_socket=Path(environ.get("DOCKER_SOCKET", "/var/run/docker.sock")),
                alert_after_failures=int(environ.get("ALERT_AFTER_FAILURES", "2")),
                reminder_hours=float(environ.get("REMINDER_HOURS", "12")),
                telegram_chat_id=environ.get("TELEGRAM_CHAT_ID", "").strip(),
                telegram_token_file=token_file,
                command_timeout=float(environ.get("COMMAND_TIMEOUT", "8")),
                recover_enabled=_env_flag(environ, "RECOVER_ENABLED", "1"),
                recover_after_failures=int(environ.get("RECOVER_AFTER_FAILURES", "1")),
                recover_cooldown_hours=float(environ.get("RECOVER_COOLDOWN_HOURS", "6")),
                recover_max_per_incident=int(environ.get("RECOVER_MAX_PER_INCIDENT", "2")),
                recover_timeout=float(environ.get("RECOVER_TIMEOUT", "45")),
            )
        except ValueError as exc:
            raise ConfigError(f"invalid setting: {exc}") from exc

    @property
    def monitors(self) -> tuple[str, ...]:
        return monitor_parts(self.monitor)

    def validate(self) -> None:
        if not all(part in MONITORS for part in self.monitors):
            raise ConfigError(
                f"SENTINEL_MONITOR must be one or more of: {', '.join(MONITORS)} "
                f"(comma-separated)"
            )
        if self.alert_after_failures < 1:
            raise ConfigError("ALERT_AFTER_FAILURES must be at least 1")
        if not math.isfinite(self.reminder_hours) or self.reminder_hours <= 0:
            raise ConfigError("REMINDER_HOURS must be positive")
        if not math.isfinite(self.command_timeout) or self.command_timeout <= 0:
            raise ConfigError("COMMAND_TIMEOUT must be positive")
        if self.recover_after_failures < 1:
            raise ConfigError("RECOVER_AFTER_FAILURES must be at least 1")
        if self.recover_max_per_incident < 1:
            raise ConfigError("RECOVER_MAX_PER_INCIDENT must be at least 1")
        if not math.isfinite(self.recover_cooldown_hours) or self.recover_cooldown_hours <= 0:
            raise ConfigError("RECOVER_COOLDOWN_HOURS must be positive")
        if not math.isfinite(self.recover_timeout) or self.recover_timeout <= 0:
            raise ConfigError("RECOVER_TIMEOUT must be positive")
        if "boinc" not in self.monitors:
            return
        if not math.isfinite(self.sample_seconds) or self.sample_seconds <= 0:
            raise ConfigError("SAMPLE_SECONDS must be positive")
        if not math.isfinite(self.total_vcpus) or self.total_vcpus <= 0:
            raise ConfigError("TOTAL_VCPUS must be positive")
        if not math.isfinite(self.cpu_threshold) or not 0 <= self.cpu_threshold <= 100:
            raise ConfigError("CPU_THRESHOLD must be between 0 and 100")


class BoincProbe:
    def __init__(
        self,
        settings: Settings,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.settings = settings
        self.runner = runner
        self.sleeper = sleeper
        self.monotonic = monotonic

    def _command(self, args: list[str], cwd: Optional[Path] = None) -> subprocess.CompletedProcess[str]:
        return self.runner(
            args,
            cwd=str(cwd) if cwd else None,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=self.settings.command_timeout,
            check=False,
        )

    def _control_group(self) -> Optional[str]:
        result = self._command(
            [
                "/usr/bin/systemctl",
                "show",
                "--property=ControlGroup",
                "--value",
                self.settings.service_name,
            ]
        )
        if result.returncode != 0:
            return None
        value = result.stdout.strip()
        return value if value.startswith("/") else None

    def _cpu_usage_usec(self, control_group: Optional[str]) -> Optional[int]:
        if control_group is None:
            return None
        parts = Path(control_group.lstrip("/")).parts
        if ".." in parts:
            return None
        path = self.settings.cgroup_root.joinpath(*parts, "cpu.stat")
        try:
            for line in path.read_text(encoding="ascii").splitlines():
                key, _, value = line.partition(" ")
                if key == "usage_usec":
                    return int(value.strip())
        except (OSError, ValueError):
            return None
        return None

    def _service_active(self) -> tuple[bool, Optional[str]]:
        try:
            result = self._command(
                [
                    "/usr/bin/systemctl",
                    "show",
                    "--property=ActiveState",
                    "--value",
                    self.settings.service_name,
                ]
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, f"service query {type(exc).__name__}"
        state = result.stdout.strip()
        if result.returncode != 0:
            return False, f"service query exit {result.returncode}"
        return state == "active", None

    def _executing_tasks(self) -> tuple[int, Optional[str]]:
        try:
            result = self._command(
                [self.settings.boinccmd, "--get_tasks"], cwd=self.settings.boinc_data_dir
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return 0, f"task query {type(exc).__name__}"
        if result.returncode != 0:
            return 0, f"task query exit {result.returncode}"
        return len(EXECUTING_RE.findall(result.stdout)), None

    def measure(self) -> CheckResult:
        errors: list[str] = []
        try:
            control_group = self._control_group()
        except (OSError, subprocess.TimeoutExpired) as exc:
            control_group = None
            errors.append(f"cgroup query {type(exc).__name__}")
        before = self._cpu_usage_usec(control_group)
        started = self.monotonic()
        self.sleeper(self.settings.sample_seconds)
        elapsed = max(self.monotonic() - started, 0.001)
        after = self._cpu_usage_usec(control_group)

        if before is None or after is None:
            cpu_percent = 0.0
            errors.append("cgroup CPU unavailable")
        else:
            delta = after - before
            if delta < 0:
                # The service restarted and its accounting counter reset mid-sample.
                delta = after
                errors.append("cgroup CPU counter reset")
            cpu_percent = max(0.0, delta / 1_000_000 / elapsed / self.settings.total_vcpus * 100)

        active, active_error = self._service_active()
        tasks, task_error = self._executing_tasks()
        if active_error:
            errors.append(active_error)
        if task_error:
            errors.append(task_error)
        return CheckResult(active, tasks, round(cpu_percent, 2), errors)


class RecoveryRunner:
    """Ask the account manager for a fresh project assignment.

    This is a destructive call, not a query. The manager may answer with
    <detach/>, and client/acct_mgr.cpp acts on it through detach_project()
    immediately, discarding whatever the detached project had in flight. Only
    call it through recovery_block_reason(), which enforces the cooldown that
    keeps a detach from cascading into the next check's failure.
    """

    def __init__(
        self,
        settings: Settings,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ):
        self.settings = settings
        self.runner = runner

    def run(self) -> tuple[bool, str]:
        args = [self.settings.boinccmd, "--acct_mgr", "sync"]
        try:
            result = self.runner(
                args,
                cwd=str(self.settings.boinc_data_dir),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.settings.recover_timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, f"acct_mgr sync {type(exc).__name__}"
        if result.returncode != 0:
            return False, f"acct_mgr sync exit {result.returncode}"
        return True, "acct_mgr sync ok"


def boinc_target_result(result: CheckResult, threshold: float) -> TargetResult:
    return TargetResult(
        target_id=BOINC_TARGET,
        reasons=result.reasons(threshold),
        details={
            "service_active": result.service_active,
            "executing_tasks": result.executing_tasks,
            "cpu_percent": result.cpu_percent,
        },
        recovery_hint=None if result.starved() else "failure is not a work shortage",
    )


class BoincMonitor:
    """Option 1: the single BOINC target, recovered by account manager sync."""

    name = "boinc"

    def __init__(self, settings: Settings, probe: Any = None, recovery: Any = None):
        self.settings = settings
        self.probe = probe if probe is not None else BoincProbe(settings)
        self.recovery = recovery if recovery is not None else RecoveryRunner(settings)

    def target_ids(self) -> list[str]:
        return [BOINC_TARGET]

    def check(self) -> list[TargetResult]:
        return [boinc_target_result(self.probe.measure(), self.settings.cpu_threshold)]

    def recover(self, target_id: str) -> tuple[bool, str]:
        return self.recovery.run()


@dataclass(frozen=True)
class Target:
    kind: str
    value: str
    pattern: Optional[re.Pattern[str]] = field(default=None, compare=False)

    @property
    def target_id(self) -> str:
        return f"{self.kind}:{self.value}"


def _normalize_unit(value: str, number: int) -> str:
    if value.startswith("-") or not UNIT_NAME_RE.match(value):
        raise ConfigError(f"targets line {number}: invalid unit name {value!r}")
    suffix = value.rsplit(".", 1)[1] if "." in value else ""
    if suffix == "service":
        return value
    if suffix in OTHER_UNIT_TYPES:
        raise ConfigError(f"targets line {number}: only .service units are supported: {value!r}")
    return f"{value}.service"


def parse_targets(text: str, kinds: tuple[str, ...] = MONITOR_KINDS["process"]) -> list[Target]:
    targets: list[Target] = []
    seen: set[str] = set()
    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        kind = parts[0]
        value = parts[1].strip() if len(parts) > 1 else ""
        if kind not in kinds:
            raise ConfigError(
                f"targets line {number}: unknown kind {kind!r} (expected {', '.join(kinds)})"
            )
        if not value:
            raise ConfigError(f"targets line {number}: {kind} needs a value")
        pattern = None
        if kind == "service":
            value = _normalize_unit(value, number)
        elif kind == "container":
            value = value.lstrip("/")
            if not CONTAINER_NAME_RE.match(value):
                raise ConfigError(f"targets line {number}: invalid container name {value!r}")
        elif kind == "cmdline":
            try:
                pattern = re.compile(value)
            except re.error as exc:
                raise ConfigError(f"targets line {number}: invalid regex: {exc}") from exc
        target = Target(kind, value, pattern)
        if target.target_id in seen:
            raise ConfigError(f"targets line {number}: duplicate target {target.target_id}")
        seen.add(target.target_id)
        targets.append(target)
    if not targets:
        raise ConfigError("targets file has no targets")
    return targets


def load_targets(path: Path, kinds: tuple[str, ...] = MONITOR_KINDS["process"]) -> list[Target]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigError(f"targets file not found: {path}") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"targets file unreadable: {path}: {type(exc).__name__}") from exc
    return parse_targets(text, kinds)


@dataclass
class ProcessInfo:
    pid: int
    comm: str
    argv: list[str]
    start_ticks: int


def scan_processes(proc_root: Path, exclude: set[int]) -> list[ProcessInfo]:
    """List live user-space processes from /proc.

    Only world-readable files are used. The unit runs as root without
    capabilities, so /proc/<pid>/exe of other users' processes is off limits.
    """
    processes: list[ProcessInfo] = []
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid in exclude:
            continue
        try:
            stat = (entry / "stat").read_text(encoding="utf-8", errors="replace")
            cmdline = (entry / "cmdline").read_bytes()
        except OSError:
            continue  # Exited mid-scan.
        head, separator, tail = stat.rpartition(")")
        if not separator:
            continue
        fields = tail.split()
        # Fields after the comm start at field 3 (state); starttime is field 22.
        if len(fields) < 20 or fields[0] == "Z":
            continue
        try:
            start_ticks = int(fields[19])
        except ValueError:
            continue
        argv = [part.decode("utf-8", "replace") for part in cmdline.split(b"\0")]
        while argv and not argv[-1]:
            argv.pop()
        if not argv:
            continue  # Kernel threads have no command line.
        processes.append(ProcessInfo(pid, head.partition("(")[2], argv, start_ticks))
    return processes


def process_matches(target: Target, process: ProcessInfo) -> bool:
    if target.kind == "cmdline":
        assert target.pattern is not None
        return target.pattern.search(" ".join(process.argv)) is not None
    name = target.value
    if process.comm == name:
        return True
    if len(name) > COMM_LENGTH and process.comm == name[:COMM_LENGTH]:
        return True
    return os.path.basename(process.argv[0]) == name


def _optional_int(value: Optional[str]) -> Optional[int]:
    try:
        parsed = int(value) if value is not None else None
    except ValueError:
        return None
    return parsed if parsed is not None and parsed >= 0 else None


class ProcessMonitor:
    """Option 2: registered systemd services and processes.

    Each target is alive or not, and a restart since the previous check is
    reported separately. Only service targets have a recovery action.
    """

    name = "process"
    SERVICE_PROPERTIES = ("LoadState", "ActiveState", "SubState", "MainPID", "NRestarts")

    def __init__(
        self,
        settings: Settings,
        targets: list[Target],
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        self_pid: Optional[int] = None,
    ):
        self.settings = settings
        self.targets = targets
        self.runner = runner
        self.self_pid = os.getpid() if self_pid is None else self_pid

    def target_ids(self) -> list[str]:
        return [target.target_id for target in self.targets]

    def _systemctl(self, args: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        return self.runner(
            [self.settings.systemctl, *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )

    def _check_service(self, target: Target) -> TargetResult:
        properties: dict[str, str] = {}
        errors: list[str] = []
        try:
            # --value would drop the names, so parse Key=Value lines instead.
            result = self._systemctl(
                ["show", f"--property={','.join(self.SERVICE_PROPERTIES)}", "--", target.value],
                self.settings.command_timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"service query {type(exc).__name__}")
        else:
            if result.returncode != 0:
                errors.append(f"service query exit {result.returncode}")
            else:
                for line in result.stdout.splitlines():
                    key, separator, value = line.partition("=")
                    if separator:
                        properties[key.strip()] = value.strip()
                if not {"LoadState", "ActiveState"}.issubset(properties):
                    errors.append("service query incomplete")

        details = {
            "load_state": properties.get("LoadState"),
            "active_state": properties.get("ActiveState"),
            "sub_state": properties.get("SubState"),
            "main_pid": _optional_int(properties.get("MainPID")),
            "n_restarts": _optional_int(properties.get("NRestarts")),
        }
        if errors:
            return TargetResult(
                target.target_id, errors, details, probe_ok=False, recovery_hint="probe error"
            )
        reasons: list[str] = []
        hint: Optional[str] = None
        if details["load_state"] != "loaded":
            reasons.append(f"LoadState={details['load_state']}")
            hint = "unit is not loaded"
        elif details["active_state"] != "active":
            reasons.append(f"ActiveState={details['active_state']}")
            # Only a crashed unit is restarted. inactive usually means an
            # administrator stopped it, and activating/deactivating means
            # systemd is already acting on it.
            if details["active_state"] != "failed":
                hint = f"ActiveState={details['active_state']} is not failed"
        return TargetResult(
            target.target_id,
            reasons,
            details,
            restart_marker=details["n_restarts"],
            recovery_hint=hint,
        )

    def _check_processes(self, targets: list[Target]) -> list[TargetResult]:
        try:
            processes = scan_processes(self.settings.proc_root, {self.self_pid})
        except OSError as exc:
            error = f"process scan {type(exc).__name__}"
            return [
                TargetResult(
                    target.target_id,
                    [error],
                    {"count": 0},
                    probe_ok=False,
                    recovery_hint="probe error",
                )
                for target in targets
            ]
        results = []
        for target in targets:
            matches = [process for process in processes if process_matches(target, process)]
            results.append(
                TargetResult(
                    target.target_id,
                    [] if matches else ["no matching process"],
                    {"count": len(matches)},
                    # A restart means every process seen last time is gone: even
                    # the oldest match now started after the newest one back then.
                    restart_marker=max(process.start_ticks for process in matches) if matches else None,
                    restart_compare=min(process.start_ticks for process in matches) if matches else None,
                    recovery_hint="process targets have no restart action",
                )
            )
        return results

    def check(self) -> list[TargetResult]:
        by_id: dict[str, TargetResult] = {}
        process_targets = [target for target in self.targets if target.kind != "service"]
        if process_targets:
            for result in self._check_processes(process_targets):
                by_id[result.target_id] = result
        for target in self.targets:
            if target.kind == "service":
                by_id[target.target_id] = self._check_service(target)
        return [by_id[target.target_id] for target in self.targets]

    def recover(self, target_id: str) -> tuple[bool, str]:
        unit = target_id.partition(":")[2]
        # reset-failed clears a start-limit hit that would refuse the restart.
        # Sentinel's own cooldown and per-incident budget replace that limit.
        for verb in ("reset-failed", "restart"):
            try:
                result = self._systemctl([verb, "--", unit], self.settings.recover_timeout)
            except (OSError, subprocess.TimeoutExpired) as exc:
                return False, f"systemctl {verb} {type(exc).__name__}"
            if result.returncode != 0:
                return False, f"systemctl {verb} exit {result.returncode}"
        return True, "systemctl restart ok"


class UnixHTTPConnection(http.client.HTTPConnection):
    """HTTP over the Docker Engine's unix socket, without the docker CLI."""

    def __init__(self, socket_path: Path, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(str(self.socket_path))
        except OSError:
            sock.close()
            raise
        self.sock = sock


class DockerClient:
    def __init__(self, socket_path: Path):
        self.socket_path = socket_path

    def request(self, method: str, path: str, timeout: float) -> tuple[int, bytes]:
        connection = UnixHTTPConnection(self.socket_path, timeout)
        try:
            connection.request(method, path, headers={"Host": "docker"})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()


# Exit codes of a container stopped on purpose: clean exit, SIGTERM from
# `docker stop`, and SIGKILL once its grace period ran out.
STOP_EXIT_CODES = {0, 137, 143}


class DockerMonitor:
    """Option 3: registered Docker containers, through the Engine API socket.

    A container is alive while it runs and its healthcheck, if any, is not
    unhealthy. RestartCount counts restart-policy restarts the way NRestarts
    does for services.
    """

    name = "docker"

    def __init__(self, settings: Settings, targets: list[Target], client: Any = None):
        self.settings = settings
        self.targets = targets
        self.client = client if client is not None else DockerClient(settings.docker_socket)
        self.actions: dict[str, str] = {}

    def target_ids(self) -> list[str]:
        return [target.target_id for target in self.targets]

    def _path(self, container: str, suffix: str) -> str:
        return f"/containers/{urllib.parse.quote(container, safe='')}/{suffix}"

    def _check_container(self, target: Target) -> TargetResult:
        empty = {"status": None, "health": None, "restart_count": None, "exit_code": None}
        try:
            status, body = self.client.request(
                "GET", self._path(target.value, "json"), self.settings.command_timeout
            )
        except (OSError, http.client.HTTPException) as exc:
            reason = f"docker query {type(exc).__name__}"
            return TargetResult(target.target_id, [reason], empty, probe_ok=False, recovery_hint="probe error")
        if status == 404:
            return TargetResult(
                target.target_id, ["container not found"], empty, recovery_hint="container not found"
            )
        try:
            if status != 200:
                raise ValueError(f"HTTP {status}")
            data = json.loads(body.decode("utf-8"))
            state = data["State"]
            if not isinstance(state, dict):
                raise TypeError("State is not an object")
        except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
            detail = str(exc) if isinstance(exc, ValueError) and str(exc).startswith("HTTP") else type(exc).__name__
            return TargetResult(
                target.target_id, [f"docker query {detail}"], empty, probe_ok=False, recovery_hint="probe error"
            )

        health_block = state.get("Health")
        health = health_block.get("Status") if isinstance(health_block, dict) else None
        if not _is_optional_str(health):
            health = None
        restart_count = data.get("RestartCount")
        exit_code = state.get("ExitCode")
        details = {
            "status": state.get("Status") if isinstance(state.get("Status"), str) else None,
            "health": health,
            "restart_count": restart_count if _is_nonnegative_int(restart_count) else None,
            "exit_code": exit_code if isinstance(exit_code, int) and not isinstance(exit_code, bool) else None,
        }
        reasons: list[str] = []
        hint: Optional[str] = None
        if details["status"] != "running":
            reasons.append(f"Status={details['status']} ExitCode={_show(details['exit_code'])}")
            crashed = details["status"] == "exited" and (
                details["exit_code"] not in STOP_EXIT_CODES or state.get("OOMKilled") is True
            )
            if crashed:
                self.actions[target.target_id] = "start"
            elif details["status"] == "exited":
                hint = "container was stopped, not crashed"
            else:
                hint = f"Status={details['status']} is not a crash"
        elif health == "unhealthy":
            reasons.append("Health=unhealthy")
            # Docker never restarts an unhealthy container by itself.
            self.actions[target.target_id] = "restart"
        return TargetResult(
            target.target_id,
            reasons,
            details,
            restart_marker=details["restart_count"],
            recovery_hint=hint,
        )

    def check(self) -> list[TargetResult]:
        self.actions.clear()
        return [self._check_container(target) for target in self.targets]

    def recover(self, target_id: str) -> tuple[bool, str]:
        action = self.actions.get(target_id, "start")
        container = target_id.partition(":")[2]
        try:
            status, _ = self.client.request(
                "POST", self._path(container, action), self.settings.recover_timeout
            )
        except (OSError, http.client.HTTPException) as exc:
            return False, f"docker {action} {type(exc).__name__}"
        if status in (204, 304):
            return True, f"docker {action} ok"
        return False, f"docker {action} HTTP {status}"


class TelegramNotifier:
    def __init__(self, chat_id: str, token_file: Optional[Path], timeout: float = 10.0):
        self.chat_id = chat_id
        self.token_file = token_file
        self.timeout = timeout

    def _token(self) -> str:
        if not self.token_file:
            return ""
        try:
            return self.token_file.read_text(encoding="utf-8").strip()
        except OSError:
            return ""

    def send(self, message: str) -> bool:
        token = self._token()
        if not token or not self.chat_id:
            LOGGER.warning("Telegram notification deferred: token or chat ID is not configured")
            return False
        payload = urllib.parse.urlencode(
            {"chat_id": self.chat_id, "text": message, "disable_web_page_preview": "true"}
        ).encode("utf-8")
        request = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=payload,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
            if response.status == 200 and body.get("ok") is True:
                return True
            LOGGER.warning("Telegram notification failed: API returned a non-success response")
        except Exception as exc:  # Do not log exception text; HTTPError URLs contain the bot token.
            LOGGER.warning("Telegram notification failed: error=%s", type(exc).__name__)
        return False


def rotate_week(state: dict[str, Any], now: datetime) -> None:
    new_key = week_key(now)
    current = state["current_week"]
    if current["week"] == new_key:
        return

    pending = state["pending_weekly"]
    if pending is None:
        pending = {
            "start_week": current["week"],
            "end_week": current["week"],
            "due_at": utc_text(weekly_due(now)),
        }
        pending.update({key: current[key] for key in COUNTER_KEYS})
    else:
        # A long Telegram outage must not grow state forever or discard counters.
        pending["end_week"] = current["week"]
        for key in COUNTER_KEYS:
            pending[key] += current[key]
    state["pending_weekly"] = pending
    state["current_week"] = _counter_block(new_key)


def handle_boot_change(
    state: dict[str, Any], boot_id: str, now: Optional[datetime] = None
) -> bool:
    if state["boot_id"] == boot_id:
        return False
    previous = state["boot_id"]
    state["boot_id"] = boot_id
    state["pending_boot_alert"] = {"detected_at": utc_text(now or utc_now())}
    for target in state["targets"].values():
        target["consecutive_failures"] = 0
        target["recoveries_this_incident"] = 0
        # Every service and process starts over on boot; that is not a restart.
        target["restart_marker"] = None
    LOGGER.info("boot ID changed previous=%s current=%s failure_streak_reset=true", previous, boot_id)
    return True


def sync_targets(state: dict[str, Any], monitor: str, target_ids: list[str]) -> None:
    if state["monitor"] != monitor:
        LOGGER.info("monitor changed previous=%s current=%s", state["monitor"], monitor)
        state["monitor"] = monitor
    targets = state["targets"]
    for target_id in list(targets):
        if target_id not in target_ids:
            del targets[target_id]
            LOGGER.info("target no longer configured, state dropped target=%s", target_id)
    for target_id in target_ids:
        targets.setdefault(target_id, default_target_state())


def restart_change(
    target_id: str, previous: Optional[int], current: Optional[int]
) -> Optional[tuple[int, str]]:
    if previous is None or current is None:
        return None
    kind = target_kind(target_id)
    if kind in COUNTER_KINDS:
        # NRestarts and RestartCount count supervisor restarts only and drop
        # back to 0 on a manual start, so only an increase is a crash restart.
        name = "NRestarts" if kind == "service" else "RestartCount"
        if current > previous:
            return current - previous, f"{name} {previous}→{current}"
        return None
    # previous is the newest start seen last time, current the oldest now.
    if current > previous:
        return 1, "직전 점검의 프로세스가 모두 교체됨"
    return None


def apply_result(
    state: dict[str, Any],
    result: TargetResult,
    now: datetime,
    alert_after: int,
) -> None:
    target = state["targets"][result.target_id]
    counter = state["current_week"]
    target["last_check"] = {
        "checked_at": utc_text(now),
        "reasons": list(result.reasons),
        "details": dict(result.details),
    }

    if result.probe_ok:
        compare = result.restart_marker if result.restart_compare is None else result.restart_compare
        change = restart_change(result.target_id, target["restart_marker"], compare)
        target["restart_marker"] = result.restart_marker
        if change is not None:
            count, detail = change
            counter["restarts"] += count
            pending = target["pending_restart"]
            if pending is None:
                target["pending_restart"] = {
                    "count": count,
                    "first_at": utc_text(now),
                    "last_at": utc_text(now),
                    "detail": detail,
                }
            else:
                pending["count"] += count
                pending["last_at"] = utc_text(now)
                pending["detail"] = detail
            LOGGER.warning(
                "restart detected target=%s count=%d detail=%s", result.target_id, count, detail
            )

    if result.healthy:
        if target["incident_confirmed"] and target["incident_alert_sent"]:
            target["pending_recovery"] = {
                "started_at": target["incident_started_at"],
                "recovered_at": utc_text(now),
            }
        target["health"] = "healthy"
        target["consecutive_failures"] = 0
        target["recoveries_this_incident"] = 0
        target["incident_started_at"] = None
        target["incident_confirmed"] = False
        target["incident_alert_sent"] = False
        target["last_alert_at"] = None
        return

    counter["failures"] += 1
    target["consecutive_failures"] += 1
    if target["incident_started_at"] is None:
        target["incident_started_at"] = utc_text(now)
    if target["incident_confirmed"]:
        target["health"] = "unhealthy"
    elif target["consecutive_failures"] >= alert_after:
        target["incident_confirmed"] = True
        target["health"] = "unhealthy"
        counter["incidents"] += 1
    else:
        target["health"] = "degraded"


def recovery_block_reason(
    target: dict[str, Any],
    result: TargetResult,
    settings: Settings,
    now: datetime,
) -> Optional[str]:
    """Return None when auto-recovery may run, otherwise why it must not.

    Ordered cheapest and most decisive first so the journal line names the one
    condition that actually held the trigger back.
    """
    if not settings.recover_enabled:
        return "disabled"
    if result.healthy:
        return "check is healthy"
    if result.recovery_hint is not None:
        return result.recovery_hint
    if target["consecutive_failures"] < settings.recover_after_failures:
        return (
            f"failure streak {target['consecutive_failures']} "
            f"< {settings.recover_after_failures}"
        )
    if target["recoveries_this_incident"] >= settings.recover_max_per_incident:
        return (
            f"incident budget spent "
            f"{target['recoveries_this_incident']}/{settings.recover_max_per_incident}"
        )
    last = parse_utc(target["last_recovery_at"])
    if last is not None:
        cooldown = timedelta(hours=settings.recover_cooldown_hours)
        if now - last < cooldown:
            remaining = (cooldown - (now - last)).total_seconds() / 3600
            return f"cooldown for another {remaining:.1f}h"
    return None


def _health_label(value: str) -> str:
    return {
        "unknown": "미확인",
        "healthy": "정상",
        "degraded": "관찰 중",
        "unhealthy": "장애",
    }[value]


def _show(value: Any) -> str:
    return "?" if value is None else str(value)


def _last_check_summary(target_id: str, target: dict[str, Any]) -> str:
    check = target["last_check"]
    if check is None:
        return "측정값 없음"
    reasons = ", ".join(check["reasons"]) if check["reasons"] else "없음"
    details = check["details"]
    kind = target_kind(target_id)
    if kind == BOINC_TARGET:
        active = "active" if details["service_active"] else "inactive"
        return (
            f"service={active}, EXECUTING={details['executing_tasks']}, "
            f"CPU={details['cpu_percent']:.1f}%, 원인={reasons}"
        )
    if kind == "service":
        return (
            f"ActiveState={_show(details.get('active_state'))}, "
            f"SubState={_show(details.get('sub_state'))}, "
            f"NRestarts={_show(details.get('n_restarts'))}, 원인={reasons}"
        )
    if kind == "container":
        health = details.get("health") or "none"
        return (
            f"Status={_show(details.get('status'))}, Health={health}, "
            f"RestartCount={_show(details.get('restart_count'))}, 원인={reasons}"
        )
    return f"프로세스={details['count']}개, 원인={reasons}"


@dataclass
class Notification:
    kind: str
    message: str
    target_id: Optional[str] = None


def _target_notifications(
    target_id: str,
    target: dict[str, Any],
    now: datetime,
    hostname: str,
    reminder_hours: float,
) -> list[Notification]:
    # BOINC keeps its original wording; process targets name the target.
    boinc = target_id == BOINC_TARGET
    subject = hostname if boinc else f"{hostname} {target_id}"
    summary = _last_check_summary(target_id, target)
    notifications: list[Notification] = []

    recovery = target["pending_recovery"]
    if recovery is not None:
        if boinc:
            message = (
                f"✅ Sentinel 복구: {hostname}의 BOINC가 정상화되었습니다. "
                f"장애 시작={recovery['started_at']}, 복구={recovery['recovered_at']}; {summary}"
            )
        else:
            message = (
                f"✅ Sentinel 복구: {subject}; "
                f"장애 시작={recovery['started_at']}, 복구={recovery['recovered_at']}; {summary}"
            )
        notifications.append(Notification("recovery", message, target_id))

    attempt = target["pending_recovery_alert"]
    if attempt is not None:
        outcome = "성공" if attempt["succeeded"] else "실패"
        progress = f"({attempt['attempt']}/{attempt['max_attempts']}회차, {attempt['detail']})"
        if boinc:
            message = (
                f"🔧 Sentinel 자동복구 {outcome}: {hostname}에서 "
                f"boinccmd --acct_mgr sync 실행 {progress}; {summary}"
            )
        else:
            message = f"🔧 Sentinel 자동복구 {outcome}: {subject}; {progress}; {summary}"
        notifications.append(Notification("recovery_attempt", message, target_id))

    restart = target["pending_restart"]
    if restart is not None:
        # A crash loop is announced once, then only counted until the
        # reminder window passes and the total goes out in one message.
        last_sent = parse_utc(target["last_restart_alert_at"])
        if last_sent is None or now - last_sent >= timedelta(hours=reminder_hours):
            period = restart["first_at"]
            if restart["last_at"] != restart["first_at"]:
                period = f"{restart['first_at']}~{restart['last_at']}"
            notifications.append(
                Notification(
                    "restart",
                    f"🔁 Sentinel 재시작: {subject}; 재시작={restart['count']}회, "
                    f"감지={period}, {restart['detail']}; {summary}",
                    target_id,
                )
            )

    if target["incident_confirmed"]:
        last_alert = parse_utc(target["last_alert_at"])
        due = not target["incident_alert_sent"]
        kind = "incident"
        if last_alert is not None and now - last_alert >= timedelta(hours=reminder_hours):
            due = True
            kind = "reminder"
        if due:
            prefix = "🚨 Sentinel 장애" if kind == "incident" else "🚨 Sentinel 장애 지속"
            notifications.append(
                Notification(
                    kind,
                    f"{prefix}: {subject}; 시작={target['incident_started_at']}, "
                    f"연속 실패={target['consecutive_failures']}회; {summary}",
                    target_id,
                )
            )
    return notifications


def overall_health(state: dict[str, Any]) -> str:
    healths = [target["health"] for target in state["targets"].values()]
    if not healths:
        return "unknown"
    return max(healths, key=HEALTH_ORDER.index)


def pending_notifications(
    state: dict[str, Any], now: datetime, hostname: str, reminder_hours: float
) -> list[Notification]:
    notifications: list[Notification] = []
    reset = state["pending_state_reset_alert"]
    if reset is not None:
        notifications.append(
            Notification(
                "state_reset",
                f"⚠️ Sentinel 상태 초기화: {hostname}의 손상된 state.json을 "
                f"{reset['backup_name']}으로 보존하고 새 상태를 만들었습니다.",
            )
        )

    boot = state["pending_boot_alert"]
    if boot is not None:
        notifications.append(
            Notification("boot", f"🔄 Sentinel 재부팅 감지: {hostname}; 감지={boot['detected_at']}")
        )

    for target_id, target in state["targets"].items():
        notifications.extend(
            _target_notifications(target_id, target, now, hostname, reminder_hours)
        )

    weekly = state["pending_weekly"]
    if weekly is not None and now >= parse_utc(weekly["due_at"]):
        period = weekly["start_week"]
        if weekly["end_week"] != weekly["start_week"]:
            period = f"{weekly['start_week']}~{weekly['end_week']}"
        current = _health_label(overall_health(state))
        if state["monitor"] == "boinc":
            counts = f"점검={weekly['checks']} 실패={weekly['failures']} 장애={weekly['incidents']}"
            message = f"📊 Sentinel 주간 요약: {hostname} {period} {counts} 현재={current}"
        else:
            # One run checks every target, so failures are counted per target.
            message = (
                f"📊 Sentinel 주간 요약: {hostname} {period} 점검={weekly['checks']} "
                f"대상 실패={weekly['failures']} 장애={weekly['incidents']} "
                f"재시작={weekly['restarts']} 현재={current}"
            )
            unhealthy = [
                target_id
                for target_id, target in state["targets"].items()
                if target["health"] == "unhealthy"
            ]
            if unhealthy:
                message += f"; 장애 대상={', '.join(unhealthy)}"
        notifications.append(Notification("weekly", message))
    return notifications


def mark_notification_sent(state: dict[str, Any], notification: Notification, now: datetime) -> None:
    if notification.kind == "state_reset":
        state["pending_state_reset_alert"] = None
        return
    if notification.kind == "weekly":
        state["pending_weekly"] = None
        return
    if notification.kind == "boot":
        state["pending_boot_alert"] = None
        return
    target = state["targets"].get(notification.target_id or "")
    if target is None:
        return
    if notification.kind == "recovery":
        target["pending_recovery"] = None
    elif notification.kind == "recovery_attempt":
        target["pending_recovery_alert"] = None
    elif notification.kind == "restart":
        target["pending_restart"] = None
        target["last_restart_alert_at"] = utc_text(now)
    elif notification.kind in {"incident", "reminder"}:
        target["incident_alert_sent"] = True
        target["last_alert_at"] = utc_text(now)


def _details_text(details: dict[str, Any]) -> str:
    return " ".join(f"{key}={value}" for key, value in details.items())


class Sentinel:
    def __init__(
        self,
        settings: Settings,
        store: StateStore,
        monitor: Any,
        notifier: TelegramNotifier,
        hostname: str,
        boot_id_reader: Callable[[], str] = read_boot_id,
    ):
        self.settings = settings
        self.store = store
        self.monitor = monitor
        self.notifier = notifier
        self.hostname = hostname
        self.boot_id_reader = boot_id_reader

    def _attempt_recovery(self, state: dict[str, Any], target_id: str, now: datetime) -> None:
        target = state["targets"][target_id]
        # Write-ahead. The cooldown is burned and committed before the command
        # runs, so a crash or a kill mid-run still costs one attempt rather
        # than leaving the next check free to act all over again.
        target["last_recovery_at"] = utc_text(now)
        target["recoveries_this_incident"] += 1
        attempt = target["recoveries_this_incident"]
        self.store.save(state)

        succeeded, detail = self.monitor.recover(target_id)
        LOGGER.warning(
            "auto-recovery ran target=%s attempt=%d/%d succeeded=%s detail=%s",
            target_id,
            attempt,
            self.settings.recover_max_per_incident,
            succeeded,
            detail,
        )
        target["pending_recovery_alert"] = {
            "attempted_at": utc_text(now),
            "attempt": attempt,
            "max_attempts": self.settings.recover_max_per_incident,
            "succeeded": succeeded,
            "detail": detail,
        }
        self.store.save(state)

    def check(self, now: Optional[datetime] = None) -> int:
        with self.store.lock():
            return self._check(now or utc_now())

    def _check(self, now: datetime) -> int:
        boot_id = self.boot_id_reader()
        state, _ = self.store.load(boot_id, now, self.monitor.name)
        handle_boot_change(state, boot_id, now)
        rotate_week(state, now)
        sync_targets(state, self.monitor.name, self.monitor.target_ids())

        results = self.monitor.check()
        state["current_week"]["checks"] += 1
        for result in results:
            apply_result(state, result, now, self.settings.alert_after_failures)
            target = state["targets"][result.target_id]
            LOGGER.info(
                "check target=%s health=%s consecutive_failures=%d %s reasons=%s",
                result.target_id,
                target["health"],
                target["consecutive_failures"],
                _details_text(result.details),
                "; ".join(result.reasons) or "none",
            )

        # Commit the observation before attempting external side effects. Each
        # successful notification is then committed separately for retry safety.
        self.store.save(state)

        for result in results:
            blocked = recovery_block_reason(
                state["targets"][result.target_id], result, self.settings, now
            )
            if blocked is None:
                self._attempt_recovery(state, result.target_id, now)
            elif not result.healthy:
                LOGGER.info("auto-recovery not run target=%s: %s", result.target_id, blocked)

        for notification in pending_notifications(
            state, now, self.hostname, self.settings.reminder_hours
        ):
            if self.notifier.send(notification.message):
                mark_notification_sent(state, notification, now)
                self.store.save(state)
                LOGGER.info(
                    "notification sent kind=%s target=%s", notification.kind, notification.target_id
                )
            else:
                LOGGER.warning(
                    "notification pending kind=%s target=%s", notification.kind, notification.target_id
                )
        return 0


class CompositeMonitor:
    """Several monitors in one run, e.g. SENTINEL_MONITOR=boinc,process.

    Target IDs never collide across monitors (boinc versus kind:value), so each
    target keeps its own incident and recovery goes to the monitor that owns it.
    """

    def __init__(self, name: str, monitors: list[Any]):
        self.name = name
        self.monitors = monitors
        self.owners: dict[str, Any] = {}
        for monitor in monitors:
            for target_id in monitor.target_ids():
                self.owners[target_id] = monitor

    def target_ids(self) -> list[str]:
        return [target_id for monitor in self.monitors for target_id in monitor.target_ids()]

    def check(self) -> list[TargetResult]:
        return [result for monitor in self.monitors for result in monitor.check()]

    def recover(self, target_id: str) -> tuple[bool, str]:
        return self.owners[target_id].recover(target_id)


def build_monitor(settings: Settings) -> Any:
    parts = settings.monitors
    monitors: list[Any] = []
    if "boinc" in parts:
        monitors.append(BoincMonitor(settings))
    file_monitors = [part for part in parts if part in MONITOR_KINDS]
    if file_monitors:
        # One targets file serves every file-based monitor; each takes its own kinds.
        kinds = tuple(kind for part in file_monitors for kind in MONITOR_KINDS[part])
        targets = load_targets(settings.targets_file, kinds)
        for part in file_monitors:
            own = [target for target in targets if target.kind in MONITOR_KINDS[part]]
            if not own:
                raise ConfigError(
                    f"targets file has no {part} targets "
                    f"({', '.join(MONITOR_KINDS[part])}) for SENTINEL_MONITOR={settings.monitor}"
                )
            monitors.append(
                DockerMonitor(settings, own) if part == "docker" else ProcessMonitor(settings, own)
            )
    if len(monitors) == 1:
        return monitors[0]
    return CompositeMonitor(settings.monitor, monitors)


def build_sentinel(settings: Settings) -> Sentinel:
    return Sentinel(
        settings=settings,
        store=StateStore(settings.state_file),
        monitor=build_monitor(settings),
        notifier=TelegramNotifier(settings.telegram_chat_id, settings.telegram_token_file),
        hostname=socket.gethostname(),
    )


def check_config(settings: Settings, monitor: Any, out: Callable[[str], None] = print) -> int:
    """Print each target's current status without touching the state file."""
    out(f"monitor={monitor.name} targets={len(monitor.target_ids())}")
    for result in monitor.check():
        status = "ok  " if result.healthy else "FAIL"
        reasons = "; ".join(result.reasons) or "none"
        out(f"{status} {result.target_id} {_details_text(result.details)} reasons={reasons}")
    return 0


def configure_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s %(name)s %(message)s",
    )


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verbose", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("check", help="run one health check")
    subparsers.add_parser(
        "check-config", help="validate settings and targets and print current status"
    )
    subparsers.add_parser("show-state", help="print the current state snapshot")
    reset_parser = subparsers.add_parser("reset-state", help="backup and reset state")
    reset_parser.add_argument(
        "--yes", action="store_true", help="confirm the timestamped backup and reset"
    )
    args = parser.parse_args(argv)
    configure_logging(args.verbose)

    try:
        settings = Settings.from_environment()
        settings.validate()
        store = StateStore(settings.state_file)
        if args.command == "show-state":
            try:
                with settings.state_file.open("r", encoding="utf-8") as handle:
                    state = json.load(handle)
            except FileNotFoundError:
                print(f"no state yet: {settings.state_file}", file=sys.stderr)
                return 1
            print(json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        if args.command == "reset-state":
            if not args.yes:
                parser.error("reset-state requires --yes")
            with store.lock():
                backup = store.reset(read_boot_id(), utc_now(), settings.monitor)
            if backup:
                print(f"state reset; previous snapshot preserved at {backup}")
            else:
                print("state initialized; no previous snapshot existed")
            return 0
        if args.command == "check-config":
            return check_config(settings, build_monitor(settings))
        return build_sentinel(settings).check()
    except ConfigError as exc:
        LOGGER.error("configuration error: %s", exc)
        return 2
    except StateLockedError as exc:
        LOGGER.error("%s", exc)
        return 4
    except FutureSchemaError as exc:
        LOGGER.critical("refusing to modify newer state: %s", exc)
        return 3
    except Exception as exc:
        LOGGER.exception("sentinel failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
