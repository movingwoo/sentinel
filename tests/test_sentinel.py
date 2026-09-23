import json
import stat
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import sentinel as rg


UTC = timezone.utc
ROOT = Path(__file__).resolve().parents[1]
BOINC = rg.BOINC_TARGET


def at(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def boinc_state(boot_id, now):
    state = rg.default_state(boot_id, now)
    rg.sync_targets(state, "boinc", [BOINC])
    return state


def apply_boinc(state, check_result, now, threshold=30, alert_after=2):
    rg.apply_result(state, rg.boinc_target_result(check_result, threshold), now, alert_after)


class FakeProbe:
    def __init__(self, result):
        self.result = result

    def measure(self):
        return self.result


class FakeNotifier:
    def __init__(self, succeeds):
        self.succeeds = succeeds
        self.messages = []

    def send(self, message):
        self.messages.append(message)
        return self.succeeds


class FakeRecovery:
    def __init__(self, result=(True, "acct_mgr sync ok"), error=None):
        self.result = result
        self.error = error
        self.calls = 0

    def run(self):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.result


def boinc_sentinel(path, probe_result, recovery=None, notifier=None, **overrides):
    settings = rg.Settings(state_file=path, **overrides)
    notifier = notifier if notifier is not None else FakeNotifier(True)
    monitor = rg.BoincMonitor(
        settings, probe=FakeProbe(probe_result), recovery=recovery or FakeRecovery()
    )
    sentinel = rg.Sentinel(
        settings, rg.StateStore(path), monitor, notifier, "host", boot_id_reader=lambda: "boot"
    )
    return sentinel, notifier


class StateTests(unittest.TestCase):
    def test_atomic_state_permissions_and_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sentinel" / "state.json"
            store = rg.StateStore(path)
            state = boinc_state("boot-a", at("2026-08-10T00:00:00Z"))
            store.save(state)
            loaded, backup = store.load("boot-a", at("2026-08-10T00:00:00Z"))

            self.assertEqual(loaded, state)
            self.assertIsNone(backup)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            self.assertEqual(list(path.parent.glob(".state.json.*")), [])

    def test_corrupt_state_is_preserved_and_alert_is_pending(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text("{broken", encoding="utf-8")
            state, backup = rg.StateStore(path).load("boot-a", at("2026-08-10T00:00:00Z"))

            self.assertIsNotNone(backup)
            self.assertTrue(backup.exists())
            self.assertTrue(path.exists())
            self.assertIsNotNone(state["pending_state_reset_alert"])
            persisted = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["pending_state_reset_alert"], state["pending_state_reset_alert"])
            self.assertTrue(backup.name.startswith("state.json.corrupt-"))

    def test_invalid_target_entry_is_treated_as_corrupt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            state = rg.default_state("boot-a", at("2026-08-10T00:00:00Z"), "process")
            state["targets"]["service:a.service"] = {"health": "healthy"}
            path.write_text(json.dumps(state), encoding="utf-8")
            loaded, backup = rg.StateStore(path).load(
                "boot-a", at("2026-08-10T00:00:00Z"), "process"
            )
            self.assertIsNotNone(backup)
            self.assertEqual(loaded["targets"], {})
            self.assertEqual(loaded["monitor"], "process")

    def test_future_schema_is_not_modified(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            original = '{"schema_version":999}\n'
            path.write_text(original, encoding="utf-8")
            with self.assertRaises(rg.FutureSchemaError):
                rg.StateStore(path).load("boot-a", at("2026-08-10T00:00:00Z"))
            self.assertEqual(path.read_text(encoding="utf-8"), original)

    def test_schema_zero_is_migrated(self):
        raw = {
            "schema_version": 0,
            "boot_id": "old-boot",
            "health": "healthy",
            "consecutive_failures": 0,
            "week": "2026-W32",
            "checks": 100,
            "failures": 3,
            "incidents": 1,
        }
        state = rg.migrate_state(raw, "new-boot", at("2026-08-10T00:00:00Z"))
        self.assertEqual(state["schema_version"], rg.SCHEMA_VERSION)
        self.assertEqual(state["current_week"]["checks"], 100)
        self.assertEqual(state["current_week"]["incidents"], 1)
        self.assertEqual(state["current_week"]["restarts"], 0)
        self.assertEqual(state["targets"][BOINC]["health"], "healthy")

    def test_reset_preserves_old_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            store = rg.StateStore(path)
            old = boinc_state("boot-a", at("2026-08-10T00:00:00Z"))
            old["targets"][BOINC]["health"] = "healthy"
            store.save(old)
            backup = store.reset("boot-b", at("2026-08-11T00:00:00Z"), "process")
            current = json.loads(path.read_text(encoding="utf-8"))
            preserved = json.loads(backup.read_text(encoding="utf-8"))
            self.assertEqual(current["targets"], {})
            self.assertEqual(current["monitor"], "process")
            self.assertEqual(preserved["targets"][BOINC]["health"], "healthy")


def schema2_state():
    """A schema 2 snapshot as the previous release wrote it, mid-incident."""
    return {
        "schema_version": 2,
        "boot_id": "boot",
        "health": "unhealthy",
        "consecutive_failures": 99,
        "incident_started_at": "2026-09-01T08:30:00Z",
        "incident_confirmed": True,
        "incident_alert_sent": True,
        "last_alert_at": "2026-09-02T08:45:00Z",
        "last_check": {
            "checked_at": "2026-09-02T08:45:00Z",
            "service_active": True,
            "executing_tasks": 0,
            "cpu_percent": 0.0,
            "reasons": ["no EXECUTING task", "CPU 0.0% < 30.0%"],
        },
        "pending_recovery": None,
        "pending_recovery_alert": {
            "attempted_at": "2026-09-02T08:45:00Z",
            "attempt": 2,
            "max_attempts": 2,
            "succeeded": False,
            "detail": "acct_mgr sync exit 1",
        },
        "last_recovery_at": "2026-09-02T08:45:00Z",
        "recoveries_this_incident": 2,
        "pending_state_reset_alert": None,
        "current_week": {"week": "2026-W36", "checks": 265, "failures": 99, "incidents": 1},
        "pending_weekly": {
            "start_week": "2026-W35",
            "end_week": "2026-W35",
            "checks": 672,
            "failures": 3,
            "incidents": 1,
            "due_at": "2026-08-31T00:00:00Z",
        },
    }


class MigrationTests(unittest.TestCase):
    def test_schema_two_moves_the_boinc_incident_under_targets(self):
        state = rg.migrate_state(schema2_state(), "boot", at("2026-09-02T09:00:00Z"))

        self.assertEqual(state["schema_version"], 3)
        self.assertEqual(state["monitor"], "boinc")
        target = state["targets"][BOINC]
        self.assertEqual(target["consecutive_failures"], 99)
        self.assertTrue(target["incident_alert_sent"])
        self.assertEqual(target["recoveries_this_incident"], 2)
        self.assertEqual(target["last_recovery_at"], "2026-09-02T08:45:00Z")
        self.assertEqual(target["pending_recovery_alert"]["detail"], "acct_mgr sync exit 1")
        self.assertEqual(
            target["last_check"]["details"],
            {"service_active": True, "executing_tasks": 0, "cpu_percent": 0.0},
        )
        self.assertEqual(state["current_week"]["checks"], 265)
        self.assertEqual(state["current_week"]["restarts"], 0)
        self.assertEqual(state["pending_weekly"]["checks"], 672)
        self.assertEqual(state["pending_weekly"]["restarts"], 0)

    def test_migrated_incident_keeps_its_wording_and_recovers(self):
        state = rg.migrate_state(schema2_state(), "boot", at("2026-09-02T09:00:00Z"))
        notes = rg.pending_notifications(state, at("2026-09-02T09:00:00Z"), "host", 12)
        self.assertEqual([note.kind for note in notes], ["recovery_attempt", "weekly"])

        apply_boinc(state, rg.CheckResult(True, 1, 49.5), at("2026-09-02T09:15:00Z"))
        notes = rg.pending_notifications(state, at("2026-09-02T09:15:00Z"), "host", 12)
        self.assertEqual(notes[0].message, (
            "✅ Sentinel 복구: host의 BOINC가 정상화되었습니다. "
            "장애 시작=2026-09-01T08:30:00Z, 복구=2026-09-02T09:15:00Z; "
            "service=active, EXECUTING=1, CPU=49.5%, 원인=없음"
        ))

    def test_schema_one_gains_recovery_fields_without_losing_history(self):
        raw = schema2_state()
        raw["schema_version"] = 1
        for key in ("pending_recovery_alert", "last_recovery_at", "recoveries_this_incident"):
            del raw[key]

        state = rg.migrate_state(raw, "boot", at("2026-09-02T09:00:00Z"))

        target = state["targets"][BOINC]
        self.assertEqual(state["schema_version"], rg.SCHEMA_VERSION)
        self.assertEqual(target["consecutive_failures"], 99)
        self.assertEqual(state["current_week"]["checks"], 265)
        self.assertIsNone(target["last_recovery_at"])
        self.assertIsNone(target["pending_recovery_alert"])
        self.assertEqual(target["recoveries_this_incident"], 0)

    def test_migration_is_persisted_on_load(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text(json.dumps(schema2_state()), encoding="utf-8")
            rg.StateStore(path).load("boot", at("2026-09-02T09:00:00Z"))
            persisted = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["schema_version"], 3)
            self.assertIn(BOINC, persisted["targets"])


class BoincWordingTests(unittest.TestCase):
    """Option 1 messages must stay byte-for-byte what the previous release sent."""

    SUMMARY_BAD = "service=active, EXECUTING=0, CPU=0.0%, 원인=no EXECUTING task, CPU 0.0% < 30.0%"
    SUMMARY_GOOD = "service=active, EXECUTING=1, CPU=49.5%, 원인=없음"

    def setUp(self):
        self.now = at("2026-08-10T00:00:00Z")
        self.state = boinc_state("b", self.now)
        self.state["pending_state_reset_alert"] = {
            "detected_at": "2026-08-10T00:00:00Z",
            "backup_name": "state.json.corrupt-X",
            "error_type": "InvalidStateError",
        }
        self.state["pending_weekly"] = {
            "start_week": "2026-W31",
            "end_week": "2026-W32",
            "checks": 10,
            "failures": 2,
            "incidents": 1,
            "restarts": 0,
            "due_at": "2026-08-10T00:00:00Z",
        }
        bad = rg.CheckResult(True, 0, 0.0)
        apply_boinc(self.state, bad, self.now)
        apply_boinc(self.state, bad, self.now + timedelta(minutes=15))
        self.target = self.state["targets"][BOINC]
        self.target["pending_recovery_alert"] = {
            "attempted_at": "2026-08-10T00:00:00Z",
            "attempt": 1,
            "max_attempts": 2,
            "succeeded": True,
            "detail": "acct_mgr sync ok",
        }

    def messages(self, now):
        return [
            (note.kind, note.message)
            for note in rg.pending_notifications(self.state, now, "host", 12)
        ]

    def test_incident_round(self):
        self.assertEqual(self.messages(self.now + timedelta(minutes=15)), [
            ("state_reset", "⚠️ Sentinel 상태 초기화: host의 손상된 state.json을 "
             "state.json.corrupt-X으로 보존하고 새 상태를 만들었습니다."),
            ("recovery_attempt", "🔧 Sentinel 자동복구 성공: host에서 boinccmd --acct_mgr sync 실행 "
             f"(1/2회차, acct_mgr sync ok); {self.SUMMARY_BAD}"),
            ("incident", "🚨 Sentinel 장애: host; 시작=2026-08-10T00:00:00Z, 연속 실패=2회; "
             f"{self.SUMMARY_BAD}"),
            ("weekly", "📊 Sentinel 주간 요약: host 2026-W31~2026-W32 점검=10 실패=2 장애=1 현재=장애"),
        ])

    def test_reminder_round(self):
        rg.mark_notification_sent(
            self.state, rg.Notification("incident", "", BOINC), self.now + timedelta(minutes=15)
        )
        messages = dict(self.messages(self.now + timedelta(hours=13)))
        self.assertEqual(messages["reminder"], (
            "🚨 Sentinel 장애 지속: host; 시작=2026-08-10T00:00:00Z, 연속 실패=2회; "
            f"{self.SUMMARY_BAD}"
        ))

    def test_recovery_round(self):
        rg.mark_notification_sent(
            self.state, rg.Notification("incident", "", BOINC), self.now + timedelta(minutes=15)
        )
        apply_boinc(self.state, rg.CheckResult(True, 1, 49.5), self.now + timedelta(hours=14))
        self.target["pending_recovery_alert"].update(
            attempt=2, succeeded=False, detail="acct_mgr sync exit 1"
        )
        self.assertEqual(self.messages(self.now + timedelta(hours=14))[1:], [
            ("recovery", "✅ Sentinel 복구: host의 BOINC가 정상화되었습니다. "
             "장애 시작=2026-08-10T00:00:00Z, 복구=2026-08-10T14:00:00Z; "
             f"{self.SUMMARY_GOOD}"),
            ("recovery_attempt", "🔧 Sentinel 자동복구 실패: host에서 boinccmd --acct_mgr sync 실행 "
             f"(2/2회차, acct_mgr sync exit 1); {self.SUMMARY_GOOD}"),
            ("weekly", "📊 Sentinel 주간 요약: host 2026-W31~2026-W32 점검=10 실패=2 장애=1 현재=정상"),
        ])


class TransitionTests(unittest.TestCase):
    def setUp(self):
        self.now = at("2026-08-10T00:00:00Z")  # Monday 09:00 KST
        self.state = boinc_state("boot-a", self.now)
        self.target = self.state["targets"][BOINC]
        self.good = rg.CheckResult(True, 1, 49.5)
        self.bad = rg.CheckResult(True, 1, 12.0)

    def test_single_failure_is_degraded_without_notification(self):
        apply_boinc(self.state, self.bad, self.now)
        self.assertEqual(self.target["health"], "degraded")
        self.assertEqual(self.target["consecutive_failures"], 1)
        self.assertEqual(self.state["current_week"]["failures"], 1)
        self.assertEqual(rg.pending_notifications(self.state, self.now, "host", 12), [])

    def test_second_failure_opens_incident_then_reminds_after_12_hours(self):
        apply_boinc(self.state, self.bad, self.now)
        apply_boinc(self.state, self.bad, self.now + timedelta(minutes=15))
        notes = rg.pending_notifications(self.state, self.now + timedelta(minutes=15), "host", 12)
        self.assertEqual([note.kind for note in notes], ["incident"])
        rg.mark_notification_sent(self.state, notes[0], self.now + timedelta(minutes=15))

        early = rg.pending_notifications(self.state, self.now + timedelta(hours=12), "host", 12)
        self.assertEqual(early, [])
        due = rg.pending_notifications(
            self.state, self.now + timedelta(hours=12, minutes=15), "host", 12
        )
        self.assertEqual([note.kind for note in due], ["reminder"])
        self.assertEqual(self.state["current_week"]["incidents"], 1)

    def test_success_resets_streak_and_queues_recovery_only_for_alerted_incident(self):
        apply_boinc(self.state, self.bad, self.now)
        apply_boinc(self.state, self.good, self.now + timedelta(minutes=15))
        self.assertEqual(self.target["health"], "healthy")
        self.assertIsNone(self.target["pending_recovery"])

        apply_boinc(self.state, self.bad, self.now + timedelta(minutes=30))
        apply_boinc(self.state, self.bad, self.now + timedelta(minutes=45))
        note = rg.pending_notifications(self.state, self.now + timedelta(minutes=45), "host", 12)[0]
        rg.mark_notification_sent(self.state, note, self.now + timedelta(minutes=45))
        apply_boinc(self.state, self.good, self.now + timedelta(hours=1))
        notes = rg.pending_notifications(self.state, self.now + timedelta(hours=1), "host", 12)
        self.assertEqual([item.kind for item in notes], ["recovery"])
        self.assertEqual(self.target["consecutive_failures"], 0)

    def test_boot_change_resets_only_streak(self):
        apply_boinc(self.state, self.bad, self.now)
        self.target["last_alert_at"] = rg.utc_text(self.now)
        self.target["restart_marker"] = 7
        counters = self.state["current_week"].copy()
        changed = rg.handle_boot_change(self.state, "boot-b")
        self.assertTrue(changed)
        self.assertEqual(self.target["consecutive_failures"], 0)
        self.assertIsNone(self.target["restart_marker"])
        self.assertEqual(self.target["last_alert_at"], rg.utc_text(self.now))
        self.assertEqual(self.state["current_week"], counters)

    def test_week_roll_preserves_summary_until_due_and_merges_if_still_pending(self):
        self.state["current_week"].update(checks=10, failures=2, incidents=1, restarts=3)
        next_week_start = self.now + timedelta(days=7) - timedelta(hours=9)
        rg.rotate_week(self.state, next_week_start)
        pending = self.state["pending_weekly"]
        self.assertEqual(pending["checks"], 10)
        self.assertEqual(pending["restarts"], 3)
        before_due = next_week_start + timedelta(hours=8, minutes=59)
        self.assertEqual(rg.pending_notifications(self.state, before_due, "host", 12), [])
        at_due = next_week_start + timedelta(hours=9)
        self.assertEqual(
            [item.kind for item in rg.pending_notifications(self.state, at_due, "host", 12)],
            ["weekly"],
        )

        self.state["current_week"].update(checks=20, failures=1, incidents=0)
        rg.rotate_week(self.state, next_week_start + timedelta(days=7))
        self.assertEqual(self.state["pending_weekly"]["checks"], 30)
        self.assertEqual(self.state["pending_weekly"]["start_week"], "2026-W33")
        self.assertEqual(self.state["pending_weekly"]["end_week"], "2026-W34")


class ProbeTests(unittest.TestCase):
    def test_cpu_is_normalized_across_two_vcpus_and_tasks_are_counted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cpu_stat = root / "system.slice" / "boinc-client.service" / "cpu.stat"
            cpu_stat.parent.mkdir(parents=True)
            cpu_stat.write_text("usage_usec 1000000\n", encoding="ascii")

            def runner(args, **kwargs):
                if "--property=ControlGroup" in args:
                    output = "/system.slice/boinc-client.service\n"
                elif "--property=ActiveState" in args:
                    output = "active\n"
                else:
                    output = (
                        "active_task_state: EXECUTING\n"
                        "active_task_state: SUSPENDED\n"
                        "active_task_state: EXECUTING\n"
                    )
                return subprocess.CompletedProcess(args, 0, output, "")

            times = iter([0.0, 10.0])

            def sleeper(_seconds):
                cpu_stat.write_text("usage_usec 11000000\n", encoding="ascii")

            settings = rg.Settings(
                cgroup_root=root,
                boinc_data_dir=root,
                sample_seconds=10,
                total_vcpus=2,
            )
            result = rg.BoincProbe(
                settings, runner=runner, sleeper=sleeper, monotonic=lambda: next(times)
            ).measure()
            self.assertEqual(result.cpu_percent, 50.0)
            self.assertEqual(result.executing_tasks, 2)
            self.assertTrue(result.healthy(30))

    def test_missing_cgroup_and_failed_queries_are_abnormal(self):
        def runner(args, **kwargs):
            return subprocess.CompletedProcess(args, 1, "", "failed")

        times = iter([0.0, 10.0])
        settings = rg.Settings(sample_seconds=10)
        result = rg.BoincProbe(
            settings, runner=runner, sleeper=lambda _: None, monotonic=lambda: next(times)
        ).measure()
        self.assertFalse(result.healthy(30))
        self.assertIn("cgroup CPU unavailable", result.errors)
        self.assertIn("service inactive", result.reasons(30))
        self.assertIn("no EXECUTING task", result.reasons(30))


class SentinelIntegrationTests(unittest.TestCase):
    def test_failed_weekly_send_remains_for_next_check(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            now = at("2026-08-10T00:00:00Z")
            state = rg.default_state("boot", now - timedelta(days=7))
            state["current_week"].update(checks=672, failures=2, incidents=1)
            rg.StateStore(path).save(state)
            notifier = FakeNotifier(False)
            sentinel, _ = boinc_sentinel(path, rg.CheckResult(True, 1, 50), notifier=notifier)
            sentinel.check(now)
            persisted = json.loads(path.read_text(encoding="utf-8"))
            self.assertIsNotNone(persisted["pending_weekly"])
            self.assertEqual(len(notifier.messages), 1)

            notifier.succeeds = True
            sentinel.check(now + timedelta(minutes=15))
            persisted = json.loads(path.read_text(encoding="utf-8"))
            self.assertIsNone(persisted["pending_weekly"])
            self.assertEqual(len(notifier.messages), 2)

    def test_each_run_counts_one_check(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            sentinel, _ = boinc_sentinel(path, rg.CheckResult(True, 1, 50))
            sentinel.check(at("2026-08-11T00:00:00Z"))
            sentinel.check(at("2026-08-11T00:15:00Z"))
            persisted = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["current_week"]["checks"], 2)
            self.assertEqual(persisted["targets"][BOINC]["health"], "healthy")


class RecoveryGateTests(unittest.TestCase):
    def setUp(self):
        self.now = at("2026-09-01T12:00:00Z")
        self.state = boinc_state("boot", self.now)
        self.target = self.state["targets"][BOINC]
        self.target["consecutive_failures"] = 1
        self.settings = rg.Settings()

    def block(self, check_result, **overrides):
        settings = rg.Settings(**overrides) if overrides else self.settings
        result = rg.boinc_target_result(check_result, settings.cpu_threshold)
        return rg.recovery_block_reason(self.target, result, settings, self.now)

    def test_starved_failure_passes_the_gate_on_the_first_failure(self):
        self.assertIsNone(self.block(rg.CheckResult(True, 0, 0.0)))

    def test_healthy_check_never_triggers(self):
        self.assertEqual(self.block(rg.CheckResult(True, 1, 50.0)), "check is healthy")

    def test_dead_service_is_not_a_work_shortage(self):
        self.assertEqual(
            self.block(rg.CheckResult(False, 0, 0.0)), "failure is not a work shortage"
        )

    def test_probe_error_is_not_a_work_shortage(self):
        result = rg.CheckResult(True, 0, 0.0, ["task query PermissionError"])
        self.assertEqual(self.block(result), "failure is not a work shortage")

    def test_running_task_with_low_cpu_is_not_a_work_shortage(self):
        self.assertEqual(
            self.block(rg.CheckResult(True, 2, 5.0)), "failure is not a work shortage"
        )

    def test_disabled_switch_wins(self):
        self.assertEqual(
            self.block(rg.CheckResult(True, 0, 0.0), recover_enabled=False), "disabled"
        )

    def test_streak_shorter_than_threshold_waits(self):
        reason = self.block(rg.CheckResult(True, 0, 0.0), recover_after_failures=2)
        self.assertEqual(reason, "failure streak 1 < 2")

    def test_incident_budget_is_capped(self):
        self.target["recoveries_this_incident"] = 2
        self.assertEqual(
            self.block(rg.CheckResult(True, 0, 0.0)), "incident budget spent 2/2"
        )

    def test_cooldown_blocks_and_then_expires(self):
        self.target["last_recovery_at"] = rg.utc_text(self.now - timedelta(hours=2))
        reason = self.block(rg.CheckResult(True, 0, 0.0))
        self.assertIsNotNone(reason)
        self.assertTrue(reason.startswith("cooldown for another 4.0h"), reason)

        self.target["last_recovery_at"] = rg.utc_text(self.now - timedelta(hours=6, minutes=1))
        self.assertIsNone(self.block(rg.CheckResult(True, 0, 0.0)))


class RecoveryRunnerTests(unittest.TestCase):
    def test_sync_runs_in_the_boinc_data_dir_so_boinccmd_finds_the_rpc_password(self):
        seen = {}

        def runner(args, **kwargs):
            seen["args"] = args
            seen["cwd"] = kwargs["cwd"]
            seen["timeout"] = kwargs["timeout"]
            return subprocess.CompletedProcess(args, 0, "", "")

        settings = rg.Settings(boinc_data_dir=Path("/var/lib/boinc-client"), recover_timeout=45)
        succeeded, detail = rg.RecoveryRunner(settings, runner=runner).run()

        self.assertTrue(succeeded)
        self.assertEqual(seen["args"], ["/usr/bin/boinccmd", "--acct_mgr", "sync"])
        self.assertEqual(seen["cwd"], "/var/lib/boinc-client")
        self.assertEqual(seen["timeout"], 45)
        self.assertEqual(detail, "acct_mgr sync ok")

    def test_nonzero_exit_and_timeout_are_reported_not_raised(self):
        def failing(args, **kwargs):
            return subprocess.CompletedProcess(args, 1, "", "boom")

        succeeded, detail = rg.RecoveryRunner(rg.Settings(), runner=failing).run()
        self.assertFalse(succeeded)
        self.assertEqual(detail, "acct_mgr sync exit 1")

        def timing_out(args, **kwargs):
            raise subprocess.TimeoutExpired(args, 45)

        succeeded, detail = rg.RecoveryRunner(rg.Settings(), runner=timing_out).run()
        self.assertFalse(succeeded)
        self.assertEqual(detail, "acct_mgr sync TimeoutExpired")


def boinc_target_on_disk(path):
    return json.loads(path.read_text(encoding="utf-8"))["targets"][BOINC]


class RecoveryIntegrationTests(unittest.TestCase):
    def test_starvation_syncs_once_then_the_cooldown_holds_the_line(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            now = at("2026-09-01T12:00:00Z")
            recovery = FakeRecovery()
            sentinel, notifier = boinc_sentinel(path, rg.CheckResult(True, 0, 0.0), recovery)

            sentinel.check(now)
            persisted = boinc_target_on_disk(path)
            self.assertEqual(recovery.calls, 1)
            self.assertEqual(persisted["recoveries_this_incident"], 1)
            self.assertEqual(persisted["last_recovery_at"], rg.utc_text(now))
            # Delivered, so nothing is left pending for the next check.
            self.assertIsNone(persisted["pending_recovery_alert"])
            # Recovery acts on the first failure while the Telegram incident
            # alert still waits for ALERT_AFTER_FAILURES.
            self.assertFalse(persisted["incident_confirmed"])
            self.assertEqual(len(notifier.messages), 1)
            self.assertIn("자동복구 성공", notifier.messages[0])

            # Every subsequent check inside the cooldown must stay hands-off.
            for step in range(1, 6):
                sentinel.check(now + timedelta(minutes=15 * step))
            self.assertEqual(recovery.calls, 1)
            self.assertEqual(boinc_target_on_disk(path)["recoveries_this_incident"], 1)

    def test_cooldown_expiry_allows_a_second_attempt_then_the_budget_stops_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            now = at("2026-09-01T12:00:00Z")
            recovery = FakeRecovery()
            sentinel, _ = boinc_sentinel(path, rg.CheckResult(True, 0, 0.0), recovery)

            sentinel.check(now)
            sentinel.check(now + timedelta(hours=7))
            self.assertEqual(recovery.calls, 2)
            sentinel.check(now + timedelta(hours=14))
            self.assertEqual(recovery.calls, 2, "incident budget must cap the attempts")
            self.assertEqual(boinc_target_on_disk(path)["recoveries_this_incident"], 2)

    def test_recovering_resets_the_budget_but_keeps_the_cooldown(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            now = at("2026-09-01T12:00:00Z")
            recovery = FakeRecovery()
            sentinel, _ = boinc_sentinel(path, rg.CheckResult(True, 0, 0.0), recovery)
            sentinel.check(now)

            healthy, _ = boinc_sentinel(path, rg.CheckResult(True, 1, 50.0), recovery)
            healthy.check(now + timedelta(minutes=15))
            persisted = boinc_target_on_disk(path)
            self.assertEqual(persisted["recoveries_this_incident"], 0)
            self.assertEqual(persisted["last_recovery_at"], rg.utc_text(now))

            # Flapping back into starvation must not sync again inside the cooldown.
            sentinel.check(now + timedelta(minutes=30))
            self.assertEqual(recovery.calls, 1)

    def test_cooldown_is_committed_before_the_sync_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            now = at("2026-09-01T12:00:00Z")
            recovery = FakeRecovery(error=RuntimeError("killed mid-sync"))
            sentinel, _ = boinc_sentinel(path, rg.CheckResult(True, 0, 0.0), recovery)

            with self.assertRaises(RuntimeError):
                sentinel.check(now)

            persisted = boinc_target_on_disk(path)
            self.assertEqual(persisted["last_recovery_at"], rg.utc_text(now))
            self.assertEqual(persisted["recoveries_this_incident"], 1)

    def test_failed_sync_is_reported_and_still_costs_an_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            now = at("2026-09-01T12:00:00Z")
            recovery = FakeRecovery(result=(False, "acct_mgr sync exit 1"))
            sentinel, notifier = boinc_sentinel(path, rg.CheckResult(True, 0, 0.0), recovery)

            sentinel.check(now)
            self.assertEqual(boinc_target_on_disk(path)["recoveries_this_incident"], 1)
            self.assertIn("자동복구 실패", notifier.messages[0])
            self.assertIn("acct_mgr sync exit 1", notifier.messages[0])

    def test_undelivered_recovery_alert_survives_for_the_next_check(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            now = at("2026-09-01T12:00:00Z")
            sentinel, _ = boinc_sentinel(
                path, rg.CheckResult(True, 0, 0.0), notifier=FakeNotifier(False)
            )
            sentinel.check(now)
            persisted = boinc_target_on_disk(path)
            self.assertIsNotNone(persisted["pending_recovery_alert"])
            self.assertEqual(persisted["pending_recovery_alert"]["attempt"], 1)


class SettingsTests(unittest.TestCase):
    def env(self, **values):
        from unittest import mock

        return mock.patch.dict("os.environ", values, clear=True)

    def test_monitor_defaults_to_boinc_for_existing_installs(self):
        with self.env():
            settings = rg.Settings.from_environment()
        self.assertEqual(settings.monitor, "boinc")
        settings.validate()

    def test_unknown_monitor_is_rejected(self):
        with self.env(SENTINEL_MONITOR="glances"):
            settings = rg.Settings.from_environment()
        with self.assertRaises(rg.ConfigError):
            settings.validate()

    def test_process_monitor_ignores_boinc_only_settings(self):
        rg.Settings(monitor="process", total_vcpus=0, cpu_threshold=500).validate()
        with self.assertRaises(rg.ConfigError):
            rg.Settings(monitor="boinc", total_vcpus=0).validate()

    def test_unparsable_number_is_a_config_error(self):
        with self.env(ALERT_AFTER_FAILURES="two"):
            with self.assertRaises(rg.ConfigError):
                rg.Settings.from_environment()

    def test_targets_file_path_is_configurable(self):
        with self.env(SENTINEL_MONITOR="Process", TARGETS_FILE="/tmp/targets"):
            settings = rg.Settings.from_environment()
        self.assertEqual(settings.monitor, "process")
        self.assertEqual(settings.targets_file, Path("/tmp/targets"))


class TargetParserTests(unittest.TestCase):
    def test_kinds_comments_and_blank_lines(self):
        targets = rg.parse_targets(
            "# comment\n"
            "\n"
            "service tailscaled.service\n"
            "  service caddy\n"
            "process my server\n"
            "cmdline ^/usr/bin/python3 /opt/bot/main\\.py\n"
        )
        self.assertEqual(
            [target.target_id for target in targets],
            [
                "service:tailscaled.service",
                "service:caddy.service",
                "process:my server",
                "cmdline:^/usr/bin/python3 /opt/bot/main\\.py",
            ],
        )
        self.assertIsNotNone(targets[3].pattern)

    def assertRejected(self, text, fragment):
        with self.assertRaises(rg.ConfigError) as caught:
            rg.parse_targets(text)
        self.assertIn(fragment, str(caught.exception))

    def test_errors_name_the_line(self):
        self.assertRejected("service a\nprogram b\n", "line 2: unknown kind 'program'")
        self.assertRejected("process\n", "line 1: process needs a value")
        self.assertRejected("service --help\n", "line 1: invalid unit name")
        self.assertRejected("service a b\n", "line 1: invalid unit name")
        self.assertRejected("service sshd.socket\n", "only .service units")
        self.assertRejected("cmdline (\n", "line 1: invalid regex")
        self.assertRejected("service a\nservice a.service\n", "line 2: duplicate target")

    def test_file_without_targets_is_rejected(self):
        self.assertRejected("# nothing\n\n", "no targets")

    def test_missing_file_is_a_config_error(self):
        with self.assertRaises(rg.ConfigError):
            rg.load_targets(Path("/nonexistent/sentinel/targets"))


def systemctl_show(**properties):
    return "".join(f"{key}={value}\n" for key, value in properties.items())


class FakeSystemctl:
    def __init__(self, outputs=None):
        self.outputs = outputs or {}
        self.calls = []
        self.fail = {}

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        verb, unit = args[1], args[-1]
        if (verb, unit) in self.fail:
            outcome = self.fail[(verb, unit)]
            if isinstance(outcome, BaseException):
                raise outcome
            return subprocess.CompletedProcess(args, outcome, "", "")
        return subprocess.CompletedProcess(args, 0, self.outputs.get(unit, ""), "")


class ServiceCheckTests(unittest.TestCase):
    def check(self, output=None, fail=None):
        runner = FakeSystemctl({"a.service": output} if output is not None else {})
        if fail is not None:
            runner.fail[("show", "a.service")] = fail
        monitor = rg.ProcessMonitor(
            rg.Settings(monitor="process"), rg.parse_targets("service a\n"), runner=runner
        )
        return monitor.check()[0], runner

    def test_active_service_is_healthy_and_reports_nrestarts(self):
        result, runner = self.check(systemctl_show(
            LoadState="loaded", ActiveState="active", SubState="running", MainPID=42, NRestarts=3
        ))
        self.assertTrue(result.healthy)
        self.assertEqual(result.restart_marker, 3)
        self.assertEqual(result.details["main_pid"], 42)
        args = runner.calls[0][0]
        self.assertEqual(args[:2], ["/usr/bin/systemctl", "show"])
        self.assertEqual(args[-2:], ["--", "a.service"])
        self.assertNotIn("--value", args)

    def test_failed_service_is_restartable(self):
        result, _ = self.check(systemctl_show(
            LoadState="loaded", ActiveState="failed", SubState="failed", MainPID=0, NRestarts=5
        ))
        self.assertEqual(result.reasons, ["ActiveState=failed"])
        self.assertIsNone(result.recovery_hint)

    def test_inactive_service_fails_but_is_left_to_the_administrator(self):
        result, _ = self.check(systemctl_show(
            LoadState="loaded", ActiveState="inactive", SubState="dead", MainPID=0, NRestarts=0
        ))
        self.assertEqual(result.reasons, ["ActiveState=inactive"])
        self.assertEqual(result.recovery_hint, "ActiveState=inactive is not failed")

    def test_missing_unit_is_not_loaded(self):
        result, _ = self.check(systemctl_show(
            LoadState="not-found", ActiveState="inactive", SubState="dead", MainPID=0, NRestarts=0
        ))
        self.assertEqual(result.reasons, ["LoadState=not-found"])
        self.assertEqual(result.recovery_hint, "unit is not loaded")

    def test_query_errors_are_failures_that_keep_the_marker(self):
        for fail, reason in (
            (1, "service query exit 1"),
            (subprocess.TimeoutExpired("systemctl", 8), "service query TimeoutExpired"),
        ):
            result, _ = self.check(fail=fail)
            self.assertEqual(result.reasons, [reason])
            self.assertFalse(result.probe_ok)
            self.assertEqual(result.recovery_hint, "probe error")
        result, _ = self.check("garbage\n")
        self.assertEqual(result.reasons, ["service query incomplete"])

    def test_restart_runs_reset_failed_then_restart(self):
        runner = FakeSystemctl()
        monitor = rg.ProcessMonitor(
            rg.Settings(monitor="process", recover_timeout=45),
            rg.parse_targets("service a\n"),
            runner=runner,
        )
        self.assertEqual(monitor.recover("service:a.service"), (True, "systemctl restart ok"))
        self.assertEqual(
            [call[0] for call in runner.calls],
            [
                ["/usr/bin/systemctl", "reset-failed", "--", "a.service"],
                ["/usr/bin/systemctl", "restart", "--", "a.service"],
            ],
        )
        self.assertEqual(runner.calls[1][1]["timeout"], 45)

        runner.fail[("restart", "a.service")] = 1
        self.assertEqual(monitor.recover("service:a.service"), (False, "systemctl restart exit 1"))
        runner.fail[("reset-failed", "a.service")] = subprocess.TimeoutExpired("systemctl", 45)
        self.assertEqual(
            monitor.recover("service:a.service"), (False, "systemctl reset-failed TimeoutExpired")
        )


class FakeProc:
    def __init__(self, root):
        self.root = Path(root)

    def add(self, pid, comm, argv, start=100, state="S"):
        entry = self.root / str(pid)
        entry.mkdir()
        fields = [state] + ["0"] * 18 + [str(start)] + ["0"] * 5
        (entry / "stat").write_text(f"{pid} ({comm}) {' '.join(fields)}\n", encoding="utf-8")
        (entry / "cmdline").write_bytes(b"".join(arg.encode() + b"\0" for arg in argv))
        return entry


class ProcessCheckTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.proc = FakeProc(self.directory.name)
        (self.proc.root / "self").mkdir()
        (self.proc.root / "meminfo").write_text("", encoding="utf-8")

    def tearDown(self):
        self.directory.cleanup()

    def check(self, targets_text, self_pid=1):
        monitor = rg.ProcessMonitor(
            rg.Settings(monitor="process", proc_root=self.proc.root),
            rg.parse_targets(targets_text),
            runner=FakeSystemctl(),
            self_pid=self_pid,
        )
        return {result.target_id: result for result in monitor.check()}

    def test_name_matches_comm_or_argv0_basename(self):
        self.proc.add(10, "caddy", ["/usr/bin/caddy", "run"], start=500)
        self.proc.add(11, "caddy", ["/usr/bin/caddy", "worker"], start=700)
        self.proc.add(12, "main.py", ["/opt/bot/main.py"], start=800)
        self.proc.add(13, "node", ["/usr/local/bin/pm2-runtime"], start=900)
        results = self.check("process caddy\nprocess main.py\nprocess pm2-runtime\nprocess nginx\n")

        self.assertEqual(results["process:caddy"].details, {"count": 2})
        self.assertEqual(results["process:caddy"].restart_marker, 500)
        self.assertTrue(results["process:main.py"].healthy)
        self.assertTrue(results["process:pm2-runtime"].healthy)
        self.assertEqual(results["process:nginx"].reasons, ["no matching process"])
        self.assertIsNone(results["process:nginx"].restart_marker)

    def test_long_names_match_the_truncated_comm(self):
        self.proc.add(10, "tailscaled-watc", ["tsw"])
        self.assertTrue(self.check("process tailscaled-watchdog\n")["process:tailscaled-watchdog"].healthy)

    def test_cmdline_regex_searches_the_joined_command_line(self):
        self.proc.add(10, "python3", ["/usr/bin/python3", "/opt/bot/main.py", "--prod"])
        self.proc.add(11, "python3", ["/usr/bin/python3", "/opt/other.py"])
        result = self.check("cmdline /opt/bot/main\\.py --prod\n")["cmdline:/opt/bot/main\\.py --prod"]
        self.assertEqual(result.details, {"count": 1})

    def test_self_kernel_threads_and_zombies_never_match(self):
        self.proc.add(1, "python3", ["/usr/bin/python3", "/usr/local/sbin/sentinel", "check"])
        self.proc.add(2, "kworker/0:1", [])
        self.proc.add(3, "sentinel", ["sentinel"], state="Z")
        result = self.check("cmdline sentinel\nprocess kworker/0:1\n")
        self.assertEqual(result["cmdline:sentinel"].reasons, ["no matching process"])
        self.assertEqual(result["process:kworker/0:1"].reasons, ["no matching process"])

    def test_process_exiting_mid_scan_is_skipped(self):
        entry = self.proc.add(10, "caddy", ["caddy"])
        (entry / "cmdline").unlink()
        self.proc.add(11, "caddy", ["caddy"], start=900)
        self.assertEqual(self.check("process caddy\n")["process:caddy"].details, {"count": 1})

    def test_comm_with_parentheses_and_spaces(self):
        self.proc.add(10, "odd) name", ["/opt/odd"])
        self.assertTrue(self.check("process odd) name\n")["process:odd) name"].healthy)

    def test_unreadable_proc_fails_every_process_target(self):
        monitor = rg.ProcessMonitor(
            rg.Settings(monitor="process", proc_root=Path("/nonexistent/proc")),
            rg.parse_targets("process a\ncmdline b\n"),
            self_pid=1,
        )
        results = monitor.check()
        self.assertEqual([result.reasons for result in results], [["process scan FileNotFoundError"]] * 2)
        self.assertFalse(any(result.probe_ok for result in results))

    def test_results_follow_the_targets_file_order(self):
        monitor = rg.ProcessMonitor(
            rg.Settings(monitor="process", proc_root=self.proc.root),
            rg.parse_targets("service a\nprocess b\nservice c\n"),
            runner=FakeSystemctl(),
            self_pid=1,
        )
        self.assertEqual(
            [result.target_id for result in monitor.check()],
            ["service:a.service", "process:b", "service:c.service"],
        )


def service_result(target_id="service:a.service", active="active", restarts=0, probe_ok=True):
    reasons = [] if active == "active" else [f"ActiveState={active}"]
    if not probe_ok:
        reasons = ["service query exit 1"]
    return rg.TargetResult(
        target_id,
        reasons,
        {
            "load_state": "loaded",
            "active_state": active,
            "sub_state": "running" if active == "active" else "failed",
            "main_pid": 42,
            "n_restarts": restarts,
        },
        restart_marker=restarts if probe_ok else None,
        probe_ok=probe_ok,
        recovery_hint=None if active == "failed" else "not failed",
    )


def process_result(target_id="process:caddy", start=100):
    return rg.TargetResult(
        target_id,
        [] if start is not None else ["no matching process"],
        {"count": 1 if start is not None else 0},
        restart_marker=start,
    )


class RestartDetectionTests(unittest.TestCase):
    def setUp(self):
        self.now = at("2026-09-23T00:00:00Z")
        self.state = rg.default_state("boot", self.now, "process")
        rg.sync_targets(self.state, "process", ["service:a.service", "process:caddy"])

    def apply(self, result, minutes=0):
        rg.apply_result(self.state, result, self.now + timedelta(minutes=minutes), 2)
        return self.state["targets"][result.target_id]

    def test_first_observation_only_records_the_baseline(self):
        target = self.apply(service_result(restarts=4))
        self.assertEqual(target["restart_marker"], 4)
        self.assertIsNone(target["pending_restart"])

    def test_nrestarts_increase_is_a_restart_and_decrease_is_a_manual_start(self):
        self.apply(service_result(restarts=3))
        target = self.apply(service_result(restarts=5), 5)
        self.assertEqual(target["pending_restart"]["count"], 2)
        self.assertEqual(target["pending_restart"]["detail"], "NRestarts 3→5")
        self.assertEqual(self.state["current_week"]["restarts"], 2)

        target["pending_restart"] = None
        target = self.apply(service_result(restarts=0), 10)
        self.assertIsNone(target["pending_restart"])
        self.assertEqual(target["restart_marker"], 0)

    def test_probe_error_keeps_the_previous_marker(self):
        self.apply(service_result(restarts=3))
        target = self.apply(service_result(probe_ok=False), 5)
        self.assertEqual(target["restart_marker"], 3)
        target = self.apply(service_result(restarts=4), 10)
        self.assertEqual(target["pending_restart"]["count"], 1)

    def test_process_start_change_is_a_restart_but_a_comeback_is_not(self):
        self.apply(process_result(start=100))
        target = self.apply(process_result(start=250), 5)
        self.assertEqual(target["pending_restart"]["count"], 1)

        target["pending_restart"] = None
        self.apply(process_result(start=None), 10)
        target = self.apply(process_result(start=400), 15)
        self.assertIsNone(target["pending_restart"])

    def test_boot_change_clears_markers(self):
        self.apply(process_result(start=100))
        rg.handle_boot_change(self.state, "boot-2")
        target = self.apply(process_result(start=5), 5)
        self.assertIsNone(target["pending_restart"])


class ProcessNotificationTests(unittest.TestCase):
    def setUp(self):
        self.now = at("2026-09-23T00:00:00Z")
        self.state = rg.default_state("boot", self.now, "process")
        rg.sync_targets(self.state, "process", ["service:a.service", "process:caddy"])

    def apply(self, result, minutes):
        rg.apply_result(self.state, result, self.now + timedelta(minutes=minutes), 2)

    def notes(self, minutes):
        return rg.pending_notifications(
            self.state, self.now + timedelta(minutes=minutes), "host", 12
        )

    def test_targets_have_independent_incidents(self):
        for minutes in (0, 5):
            self.apply(service_result(active="failed", restarts=5), minutes)
            self.apply(process_result(start=100), minutes)
        notes = self.notes(5)
        self.assertEqual([(note.kind, note.target_id) for note in notes], [
            ("incident", "service:a.service"),
        ])
        self.assertEqual(notes[0].message, (
            "🚨 Sentinel 장애: host service:a.service; 시작=2026-09-23T00:00:00Z, 연속 실패=2회; "
            "ActiveState=failed, SubState=failed, NRestarts=5, 원인=ActiveState=failed"
        ))
        self.assertEqual(self.state["targets"]["process:caddy"]["health"], "healthy")

    def test_simultaneous_incidents_recover_one_at_a_time(self):
        for minutes in (0, 5):
            self.apply(service_result(active="failed"), minutes)
            self.apply(process_result(start=None), minutes)
        for note in self.notes(5):
            rg.mark_notification_sent(self.state, note, self.now + timedelta(minutes=5))
        self.apply(service_result(), 10)
        self.apply(process_result(start=None), 10)
        notes = self.notes(10)
        self.assertEqual([(note.kind, note.target_id) for note in notes], [
            ("recovery", "service:a.service"),
        ])
        self.assertEqual(notes[0].message, (
            "✅ Sentinel 복구: host service:a.service; 장애 시작=2026-09-23T00:00:00Z, "
            "복구=2026-09-23T00:10:00Z; ActiveState=active, SubState=running, NRestarts=0, 원인=없음"
        ))
        self.assertTrue(self.state["targets"]["process:caddy"]["incident_confirmed"])

    def test_crash_loop_is_announced_once_then_summed_after_the_reminder_window(self):
        self.apply(service_result(restarts=0), 0)
        self.apply(service_result(restarts=1), 5)
        notes = self.notes(5)
        self.assertEqual(notes[0].kind, "restart")
        self.assertEqual(notes[0].message, (
            "🔁 Sentinel 재시작: host service:a.service; 재시작=1회, 감지=2026-09-23T00:05:00Z, "
            "NRestarts 0→1; ActiveState=active, SubState=running, NRestarts=1, 원인=없음"
        ))
        rg.mark_notification_sent(self.state, notes[0], self.now + timedelta(minutes=5))

        self.apply(service_result(restarts=3), 10)
        self.apply(service_result(restarts=4), 15)
        self.assertEqual(self.notes(15), [])
        due = self.notes(5 + 12 * 60)
        self.assertEqual(len(due), 1)
        self.assertIn("재시작=3회, 감지=2026-09-23T00:10:00Z~2026-09-23T00:15:00Z", due[0].message)

    def test_process_weekly_summary_lists_restarts_and_failing_targets(self):
        for minutes in (0, 5):
            self.apply(process_result(start=None), minutes)
        self.apply(service_result(), 5)
        self.state["pending_weekly"] = {
            "start_week": "2026-W38",
            "end_week": "2026-W38",
            "checks": 2016,
            "failures": 4,
            "incidents": 1,
            "restarts": 2,
            "due_at": "2026-09-21T00:00:00Z",
        }
        weekly = [note for note in self.notes(5) if note.kind == "weekly"][0]
        self.assertEqual(weekly.message, (
            "📊 Sentinel 주간 요약: host 2026-W38 점검=2016 실패=4 장애=1 재시작=2 현재=장애; "
            "장애 대상=process:caddy"
        ))

    def test_removed_target_state_is_dropped(self):
        self.apply(process_result(start=None), 0)
        rg.sync_targets(self.state, "process", ["service:a.service"])
        self.assertEqual(list(self.state["targets"]), ["service:a.service"])


class ProcessIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "state.json"
        self.proc = FakeProc(Path(self.directory.name) / "proc")
        self.proc.root.mkdir()
        self.systemctl = FakeSystemctl({
            "a.service": systemctl_show(
                LoadState="loaded", ActiveState="failed", SubState="failed", MainPID=0, NRestarts=0
            )
        })
        self.notifier = FakeNotifier(True)
        self.now = at("2026-09-23T00:00:00Z")

    def tearDown(self):
        self.directory.cleanup()

    def sentinel(self, targets="service a\nprocess caddy\n"):
        settings = rg.Settings(monitor="process", state_file=self.path, proc_root=self.proc.root)
        monitor = rg.ProcessMonitor(
            settings, rg.parse_targets(targets), runner=self.systemctl, self_pid=1
        )
        return rg.Sentinel(
            settings, rg.StateStore(self.path), monitor, self.notifier, "host",
            boot_id_reader=lambda: "boot",
        )

    def persisted(self):
        return json.loads(self.path.read_text(encoding="utf-8"))

    def test_failed_service_is_restarted_once_with_write_ahead_budget(self):
        self.proc.add(10, "caddy", ["caddy"])
        self.sentinel().check(self.now)

        verbs = [call[0][1] for call in self.systemctl.calls]
        self.assertEqual(verbs, ["show", "reset-failed", "restart"])
        target = self.persisted()["targets"]["service:a.service"]
        self.assertEqual(target["recoveries_this_incident"], 1)
        self.assertEqual(target["last_recovery_at"], rg.utc_text(self.now))
        self.assertEqual(self.notifier.messages, [
            "🔧 Sentinel 자동복구 성공: host service:a.service; systemctl restart 실행 "
            "(1/2회차, systemctl restart ok); "
            "ActiveState=failed, SubState=failed, NRestarts=0, 원인=ActiveState=failed"
        ])

        # Still failed five minutes later: the cooldown holds, the incident is announced.
        self.sentinel().check(self.now + timedelta(minutes=5))
        verbs = [call[0][1] for call in self.systemctl.calls]
        self.assertEqual(verbs.count("restart"), 1)
        self.assertIn("🚨 Sentinel 장애: host service:a.service", self.notifier.messages[-1])

    def test_disabled_recovery_never_calls_systemctl_restart(self):
        settings = rg.Settings(
            monitor="process", state_file=self.path, proc_root=self.proc.root, recover_enabled=False
        )
        monitor = rg.ProcessMonitor(settings, rg.parse_targets("service a\n"), runner=self.systemctl)
        rg.Sentinel(
            settings, rg.StateStore(self.path), monitor, self.notifier, "host",
            boot_id_reader=lambda: "boot",
        ).check(self.now)
        self.assertEqual([call[0][1] for call in self.systemctl.calls], ["show"])

    def test_partial_delivery_records_only_what_was_sent(self):
        class FlakyNotifier(FakeNotifier):
            def send(self, message):
                self.messages.append(message)
                return len(self.messages) == 1

        self.notifier = FlakyNotifier(True)
        sentinel = self.sentinel("process caddy\nprocess nginx\n")
        sentinel.check(self.now)
        sentinel.check(self.now + timedelta(minutes=5))
        targets = self.persisted()["targets"]
        self.assertTrue(targets["process:caddy"]["incident_alert_sent"])
        self.assertFalse(targets["process:nginx"]["incident_alert_sent"])

        self.notifier = FakeNotifier(True)
        self.sentinel("process caddy\nprocess nginx\n").check(self.now + timedelta(minutes=10))
        self.assertEqual(len(self.notifier.messages), 1)
        self.assertIn("process:nginx", self.notifier.messages[0])

    def test_switching_from_boinc_state_drops_the_boinc_target(self):
        state = boinc_state("boot", self.now)
        rg.StateStore(self.path).save(state)
        self.proc.add(10, "caddy", ["caddy"])
        self.sentinel("process caddy\n").check(self.now)
        persisted = self.persisted()
        self.assertEqual(persisted["monitor"], "process")
        self.assertEqual(list(persisted["targets"]), ["process:caddy"])

    def test_check_config_prints_status_without_touching_state(self):
        self.proc.add(10, "caddy", ["caddy"])
        lines = []
        settings = rg.Settings(monitor="process", state_file=self.path, proc_root=self.proc.root)
        monitor = rg.ProcessMonitor(
            settings, rg.parse_targets("service a\nprocess caddy\n"), runner=self.systemctl, self_pid=1
        )
        self.assertEqual(rg.check_config(settings, monitor, out=lines.append), 0)
        self.assertEqual(lines[0], "monitor=process targets=2")
        self.assertTrue(lines[1].startswith("FAIL service:a.service"))
        self.assertTrue(lines[2].startswith("ok   process:caddy count=1"))
        self.assertFalse(self.path.exists())


class MainTests(unittest.TestCase):
    def test_bad_targets_file_exits_with_config_error(self):
        from unittest import mock

        with tempfile.TemporaryDirectory() as directory:
            targets = Path(directory) / "targets"
            targets.write_text("program x\n", encoding="utf-8")
            env = {
                "SENTINEL_MONITOR": "process",
                "TARGETS_FILE": str(targets),
                "STATE_FILE": str(Path(directory) / "state.json"),
            }
            # configure_logging() would attach a root handler for the rest of the run.
            with mock.patch.dict("os.environ", env, clear=True), mock.patch.object(
                rg, "configure_logging"
            ):
                with self.assertLogs("sentinel", "ERROR") as logs:
                    self.assertEqual(rg.main(["check-config"]), 2)
            self.assertIn("targets line 1: unknown kind", logs.output[0])


class UnitTests(unittest.TestCase):
    def read(self, relative):
        return (ROOT / "systemd" / relative).read_text(encoding="utf-8")

    def test_base_unit_has_no_boinc_coupling(self):
        unit = self.read("sentinel.service")
        self.assertIn("User=root\n", unit)
        self.assertIn("Group=root\n", unit)
        self.assertIn("StateDirectory=sentinel\n", unit)
        self.assertIn("CapabilityBoundingSet=\n", unit)
        self.assertNotIn("boinc", unit.lower())
        # The process monitor must see other users' processes.
        self.assertNotIn("ProtectProc=", unit)

    def test_boinc_dropin_carries_the_rpc_credential_group(self):
        dropin = self.read("sentinel.service.d/boinc.conf")
        self.assertIn("SupplementaryGroups=boinc\n", dropin)
        self.assertIn("After=boinc-client.service\n", dropin)
        self.assertIn("WorkingDirectory=-/var/lib/boinc-client\n", dropin)

    def test_restart_dropin_grants_only_what_systemd_checks(self):
        dropin = self.read("sentinel.service.d/restart.conf")
        self.assertIn("CapabilityBoundingSet=CAP_SYS_ADMIN\n", dropin)

    def test_process_timer_resets_the_calendar(self):
        dropin = self.read("sentinel.timer.d/process.conf")
        self.assertIn("OnCalendar=\nOnCalendar=*:0/5\n", dropin)


if __name__ == "__main__":
    unittest.main()
