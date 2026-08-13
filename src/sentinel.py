#!/usr/bin/env python3
"""BOINC CPU Sentinel for an OCI Always Free exit node."""

from __future__ import annotations

import argparse
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


SCHEMA_VERSION = 1
KST = timezone(timedelta(hours=9), name="KST")
LOGGER = logging.getLogger("sentinel")
EXECUTING_RE = re.compile(r"^\s*active_task_state\s*:\s*EXECUTING\s*$", re.MULTILINE)


class StateError(RuntimeError):
    """Base class for state handling failures."""


class FutureSchemaError(StateError):
    """Raised when a state file was written by a newer Sentinel version."""


class InvalidStateError(StateError):
    """Raised when a state file has invalid JSON or structure."""


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


def read_boot_id(path: Path = Path("/proc/sys/kernel/random/boot_id")) -> str:
    return path.read_text(encoding="ascii").strip()


def _counter_block(key: str) -> dict[str, Any]:
    return {"week": key, "checks": 0, "failures": 0, "incidents": 0}


def default_state(boot_id: str, now: datetime) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "boot_id": boot_id,
        "health": "unknown",
        "consecutive_failures": 0,
        "incident_started_at": None,
        "incident_confirmed": False,
        "incident_alert_sent": False,
        "last_alert_at": None,
        "last_check": None,
        "pending_recovery": None,
        "pending_state_reset_alert": None,
        "current_week": _counter_block(week_key(now)),
        "pending_weekly": None,
    }


def _is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _validate_counter(value: Any, pending: bool = False) -> None:
    if not isinstance(value, dict):
        raise InvalidStateError("weekly counter is not an object")
    keys = ("start_week", "end_week") if pending else ("week",)
    for key in keys:
        if not isinstance(value.get(key), str) or not value[key]:
            raise InvalidStateError(f"weekly counter has invalid {key}")
    for key in ("checks", "failures", "incidents"):
        if not _is_nonnegative_int(value.get(key)):
            raise InvalidStateError(f"weekly counter has invalid {key}")
    if pending:
        required_utc(value.get("due_at"), "pending_weekly.due_at")


def validate_state(state: Any) -> dict[str, Any]:
    if not isinstance(state, dict):
        raise InvalidStateError("state root is not an object")
    required = {
        "schema_version",
        "boot_id",
        "health",
        "consecutive_failures",
        "incident_started_at",
        "incident_confirmed",
        "incident_alert_sent",
        "last_alert_at",
        "last_check",
        "pending_recovery",
        "pending_state_reset_alert",
        "current_week",
        "pending_weekly",
    }
    missing = required.difference(state)
    if missing:
        raise InvalidStateError(f"state is missing keys: {', '.join(sorted(missing))}")
    if state["schema_version"] != SCHEMA_VERSION:
        raise InvalidStateError("state has the wrong schema after migration")
    if not isinstance(state["boot_id"], str):
        raise InvalidStateError("boot_id is invalid")
    if state["health"] not in {"unknown", "healthy", "degraded", "unhealthy"}:
        raise InvalidStateError("health is invalid")
    if not _is_nonnegative_int(state["consecutive_failures"]):
        raise InvalidStateError("consecutive_failures is invalid")
    for key in ("incident_confirmed", "incident_alert_sent"):
        if not isinstance(state[key], bool):
            raise InvalidStateError(f"{key} is invalid")
    parse_utc(state["incident_started_at"])
    parse_utc(state["last_alert_at"])
    if state["incident_confirmed"]:
        required_utc(state["incident_started_at"], "incident_started_at")
    if state["incident_alert_sent"]:
        if not state["incident_confirmed"]:
            raise InvalidStateError("an alert cannot exist without a confirmed incident")
        required_utc(state["last_alert_at"], "last_alert_at")
    if state["last_check"] is not None:
        check = state["last_check"]
        if not isinstance(check, dict):
            raise InvalidStateError("last_check is invalid")
        required_utc(check.get("checked_at"), "last_check.checked_at")
        if not isinstance(check.get("service_active"), bool):
            raise InvalidStateError("last_check.service_active is invalid")
        if not _is_nonnegative_int(check.get("executing_tasks")):
            raise InvalidStateError("last_check.executing_tasks is invalid")
        cpu_percent = check.get("cpu_percent")
        if (
            not isinstance(cpu_percent, (int, float))
            or isinstance(cpu_percent, bool)
            or not math.isfinite(cpu_percent)
            or cpu_percent < 0
        ):
            raise InvalidStateError("last_check.cpu_percent is invalid")
        if not isinstance(check.get("reasons"), list) or not all(
            isinstance(item, str) for item in check["reasons"]
        ):
            raise InvalidStateError("last_check.reasons is invalid")
    for key in ("pending_recovery", "pending_state_reset_alert"):
        value = state[key]
        if value is not None and not isinstance(value, dict):
            raise InvalidStateError(f"{key} is invalid")
    if state["pending_recovery"] is not None:
        required_utc(state["pending_recovery"].get("started_at"), "pending_recovery.started_at")
        required_utc(
            state["pending_recovery"].get("recovered_at"), "pending_recovery.recovered_at"
        )
    if state["pending_state_reset_alert"] is not None:
        reset = state["pending_state_reset_alert"]
        required_utc(reset.get("detected_at"), "pending_state_reset_alert.detected_at")
        for key in ("backup_name", "error_type"):
            if not isinstance(reset.get(key), str) or not reset[key]:
                raise InvalidStateError(f"pending_state_reset_alert.{key} is invalid")
    _validate_counter(state["current_week"])
    if state["pending_weekly"] is not None:
        _validate_counter(state["pending_weekly"], pending=True)
    return state


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
        return validate_state(raw)

    # Schema 0 was the pre-release flat-counter format. Preserve every compatible
    # field, while initializing notification bookkeeping introduced in v1.
    migrated = default_state(str(raw.get("boot_id", boot_id)), now)
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
            migrated[key] = raw[key]
    old_week = raw.get("current_week")
    if old_week is None and any(key in raw for key in ("week", "checks", "failures", "incidents")):
        old_week = {
            "week": raw.get("week", week_key(now)),
            "checks": raw.get("checks", 0),
            "failures": raw.get("failures", 0),
            "incidents": raw.get("incidents", 0),
        }
    if old_week is not None:
        migrated["current_week"] = old_week
    return validate_state(migrated)


class StateStore:
    def __init__(self, path: Path):
        self.path = path

    def _ensure_directory(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self.path.parent, 0o700)
        except PermissionError:
            pass

    def _backup_name(self, label: str, now: datetime) -> Path:
        stamp = now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        return self.path.with_name(f"{self.path.name}.{label}-{stamp}")

    def _sync_directory(self) -> None:
        descriptor = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def load(self, boot_id: str, now: datetime) -> tuple[dict[str, Any], Optional[Path]]:
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
            state = default_state(boot_id, now)
            self.save(state)
            LOGGER.info("state initialized")
            return state, None
        except FutureSchemaError:
            raise
        except (json.JSONDecodeError, UnicodeDecodeError, InvalidStateError) as exc:
            backup = self._backup_name("corrupt", now)
            os.replace(self.path, backup)
            self._sync_directory()
            state = default_state(boot_id, now)
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

    def reset(self, boot_id: str, now: datetime) -> Optional[Path]:
        self._ensure_directory()
        backup = None
        if self.path.exists():
            backup = self._backup_name("reset", now)
            os.replace(self.path, backup)
            self._sync_directory()
        self.save(default_state(boot_id, now))
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


@dataclass
class Settings:
    state_file: Path = Path("/var/lib/sentinel/state.json")
    service_name: str = "boinc-client.service"
    boinccmd: str = "/usr/bin/boinccmd"
    boinc_data_dir: Path = Path("/var/lib/boinc-client")
    cgroup_root: Path = Path("/sys/fs/cgroup")
    sample_seconds: float = 10.0
    total_vcpus: float = 2.0
    cpu_threshold: float = 30.0
    alert_after_failures: int = 2
    reminder_hours: float = 12.0
    telegram_chat_id: str = ""
    telegram_token_file: Optional[Path] = None
    command_timeout: float = 8.0

    @classmethod
    def from_environment(cls) -> "Settings":
        credential_dir = os.environ.get("CREDENTIALS_DIRECTORY")
        token_file = (
            Path(credential_dir) / "telegram-token"
            if credential_dir
            else Path("/etc/sentinel/telegram-token")
        )
        return cls(
            state_file=Path(os.environ.get("STATE_FILE", "/var/lib/sentinel/state.json")),
            service_name=os.environ.get("BOINC_SERVICE", "boinc-client.service"),
            boinccmd=os.environ.get("BOINCCMD", "/usr/bin/boinccmd"),
            boinc_data_dir=Path(os.environ.get("BOINC_DATA_DIR", "/var/lib/boinc-client")),
            cgroup_root=Path(os.environ.get("CGROUP_ROOT", "/sys/fs/cgroup")),
            sample_seconds=float(os.environ.get("SAMPLE_SECONDS", "10")),
            total_vcpus=float(os.environ.get("TOTAL_VCPUS", "2")),
            cpu_threshold=float(os.environ.get("CPU_THRESHOLD", "30")),
            alert_after_failures=int(os.environ.get("ALERT_AFTER_FAILURES", "2")),
            reminder_hours=float(os.environ.get("REMINDER_HOURS", "12")),
            telegram_chat_id=os.environ.get("TELEGRAM_CHAT_ID", "").strip(),
            telegram_token_file=token_file,
            command_timeout=float(os.environ.get("COMMAND_TIMEOUT", "8")),
        )

    def validate(self) -> None:
        if not math.isfinite(self.sample_seconds) or self.sample_seconds <= 0:
            raise ValueError("SAMPLE_SECONDS must be positive")
        if not math.isfinite(self.total_vcpus) or self.total_vcpus <= 0:
            raise ValueError("TOTAL_VCPUS must be positive")
        if not math.isfinite(self.cpu_threshold) or not 0 <= self.cpu_threshold <= 100:
            raise ValueError("CPU_THRESHOLD must be between 0 and 100")
        if self.alert_after_failures < 1:
            raise ValueError("ALERT_AFTER_FAILURES must be at least 1")
        if not math.isfinite(self.reminder_hours) or self.reminder_hours <= 0:
            raise ValueError("REMINDER_HOURS must be positive")
        if not math.isfinite(self.command_timeout) or self.command_timeout <= 0:
            raise ValueError("COMMAND_TIMEOUT must be positive")


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
            "checks": current["checks"],
            "failures": current["failures"],
            "incidents": current["incidents"],
            "due_at": utc_text(weekly_due(now)),
        }
    else:
        # A long Telegram outage must not grow state forever or discard counters.
        pending["end_week"] = current["week"]
        for key in ("checks", "failures", "incidents"):
            pending[key] += current[key]
    state["pending_weekly"] = pending
    state["current_week"] = _counter_block(new_key)


def handle_boot_change(state: dict[str, Any], boot_id: str) -> bool:
    if state["boot_id"] == boot_id:
        return False
    previous = state["boot_id"]
    state["boot_id"] = boot_id
    state["consecutive_failures"] = 0
    LOGGER.info("boot ID changed previous=%s current=%s failure_streak_reset=true", previous, boot_id)
    return True


def apply_check(state: dict[str, Any], result: CheckResult, now: datetime, threshold: float, alert_after: int) -> None:
    reasons = result.reasons(threshold)
    healthy = not reasons
    counter = state["current_week"]
    counter["checks"] += 1
    state["last_check"] = {
        "checked_at": utc_text(now),
        "service_active": result.service_active,
        "executing_tasks": result.executing_tasks,
        "cpu_percent": result.cpu_percent,
        "reasons": reasons,
    }

    if healthy:
        if state["incident_confirmed"] and state["incident_alert_sent"]:
            state["pending_recovery"] = {
                "started_at": state["incident_started_at"],
                "recovered_at": utc_text(now),
            }
        state["health"] = "healthy"
        state["consecutive_failures"] = 0
        state["incident_started_at"] = None
        state["incident_confirmed"] = False
        state["incident_alert_sent"] = False
        state["last_alert_at"] = None
        return

    counter["failures"] += 1
    state["consecutive_failures"] += 1
    if state["incident_started_at"] is None:
        state["incident_started_at"] = utc_text(now)
    if state["incident_confirmed"]:
        state["health"] = "unhealthy"
    elif state["consecutive_failures"] >= alert_after:
        state["incident_confirmed"] = True
        state["health"] = "unhealthy"
        counter["incidents"] += 1
    else:
        state["health"] = "degraded"


def _health_label(value: str) -> str:
    return {
        "unknown": "미확인",
        "healthy": "정상",
        "degraded": "관찰 중",
        "unhealthy": "장애",
    }[value]


def _last_check_summary(state: dict[str, Any]) -> str:
    check = state["last_check"]
    if check is None:
        return "측정값 없음"
    reasons = ", ".join(check["reasons"]) if check["reasons"] else "없음"
    active = "active" if check["service_active"] else "inactive"
    return (
        f"service={active}, EXECUTING={check['executing_tasks']}, "
        f"CPU={check['cpu_percent']:.1f}%, 원인={reasons}"
    )


@dataclass
class Notification:
    kind: str
    message: str


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

    recovery = state["pending_recovery"]
    if recovery is not None:
        notifications.append(
            Notification(
                "recovery",
                f"✅ Sentinel 복구: {hostname}의 BOINC가 정상화되었습니다. "
                f"장애 시작={recovery['started_at']}, 복구={recovery['recovered_at']}; "
                f"{_last_check_summary(state)}",
            )
        )

    if state["incident_confirmed"]:
        last_alert = parse_utc(state["last_alert_at"])
        due = not state["incident_alert_sent"]
        kind = "incident"
        if last_alert is not None and now - last_alert >= timedelta(hours=reminder_hours):
            due = True
            kind = "reminder"
        if due:
            prefix = "🚨 Sentinel 장애" if kind == "incident" else "🚨 Sentinel 장애 지속"
            notifications.append(
                Notification(
                    kind,
                    f"{prefix}: {hostname}; 시작={state['incident_started_at']}, "
                    f"연속 실패={state['consecutive_failures']}회; {_last_check_summary(state)}",
                )
            )

    weekly = state["pending_weekly"]
    if weekly is not None and now >= parse_utc(weekly["due_at"]):
        period = weekly["start_week"]
        if weekly["end_week"] != weekly["start_week"]:
            period = f"{weekly['start_week']}~{weekly['end_week']}"
        notifications.append(
            Notification(
                "weekly",
                f"📊 Sentinel 주간 요약: {hostname} {period} "
                f"점검={weekly['checks']} 실패={weekly['failures']} 장애={weekly['incidents']} "
                f"현재={_health_label(state['health'])}",
            )
        )
    return notifications


def mark_notification_sent(state: dict[str, Any], notification: Notification, now: datetime) -> None:
    if notification.kind == "state_reset":
        state["pending_state_reset_alert"] = None
    elif notification.kind == "recovery":
        state["pending_recovery"] = None
    elif notification.kind in {"incident", "reminder"}:
        state["incident_alert_sent"] = True
        state["last_alert_at"] = utc_text(now)
    elif notification.kind == "weekly":
        state["pending_weekly"] = None


class Sentinel:
    def __init__(
        self,
        settings: Settings,
        store: StateStore,
        probe: BoincProbe,
        notifier: TelegramNotifier,
        hostname: str,
        boot_id_reader: Callable[[], str] = read_boot_id,
    ):
        self.settings = settings
        self.store = store
        self.probe = probe
        self.notifier = notifier
        self.hostname = hostname
        self.boot_id_reader = boot_id_reader

    def check(self, now: Optional[datetime] = None) -> int:
        now = now or utc_now()
        boot_id = self.boot_id_reader()
        state, _ = self.store.load(boot_id, now)
        handle_boot_change(state, boot_id)
        rotate_week(state, now)

        result = self.probe.measure()
        apply_check(
            state,
            result,
            now,
            self.settings.cpu_threshold,
            self.settings.alert_after_failures,
        )
        LOGGER.info(
            "check health=%s service_active=%s executing_tasks=%d cpu_percent=%.2f "
            "threshold=%.2f consecutive_failures=%d reasons=%s",
            state["health"],
            result.service_active,
            result.executing_tasks,
            result.cpu_percent,
            self.settings.cpu_threshold,
            state["consecutive_failures"],
            "; ".join(state["last_check"]["reasons"]) or "none",
        )

        # Commit the observation before attempting external side effects. Each
        # successful notification is then committed separately for retry safety.
        self.store.save(state)
        for notification in pending_notifications(
            state, now, self.hostname, self.settings.reminder_hours
        ):
            if self.notifier.send(notification.message):
                mark_notification_sent(state, notification, now)
                self.store.save(state)
                LOGGER.info("notification sent kind=%s", notification.kind)
            else:
                LOGGER.warning("notification pending kind=%s", notification.kind)
        return 0


def build_sentinel(settings: Settings) -> Sentinel:
    return Sentinel(
        settings=settings,
        store=StateStore(settings.state_file),
        probe=BoincProbe(settings),
        notifier=TelegramNotifier(settings.telegram_chat_id, settings.telegram_token_file),
        hostname=socket.gethostname(),
    )


def configure_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s %(name)s %(message)s",
    )


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verbose", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("check", help="run one BOINC health check")
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
            with settings.state_file.open("r", encoding="utf-8") as handle:
                state = json.load(handle)
            print(json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        if args.command == "reset-state":
            if not args.yes:
                parser.error("reset-state requires --yes")
            backup = store.reset(read_boot_id(), utc_now())
            if backup:
                print(f"state reset; previous snapshot preserved at {backup}")
            else:
                print("state initialized; no previous snapshot existed")
            return 0
        return build_sentinel(settings).check()
    except FutureSchemaError as exc:
        LOGGER.critical("refusing to modify newer state: %s", exc)
        return 3
    except Exception as exc:
        LOGGER.exception("sentinel failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
