import json
import os
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


def at(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


class StateTests(unittest.TestCase):
    def test_atomic_state_permissions_and_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sentinel" / "state.json"
            store = rg.StateStore(path)
            state = rg.default_state("boot-a", at("2026-08-10T00:00:00Z"))
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
        self.assertEqual(state["schema_version"], 1)
        self.assertEqual(state["current_week"]["checks"], 100)
        self.assertEqual(state["current_week"]["incidents"], 1)

    def test_reset_preserves_old_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            store = rg.StateStore(path)
            old = rg.default_state("boot-a", at("2026-08-10T00:00:00Z"))
            old["health"] = "healthy"
            store.save(old)
            backup = store.reset("boot-b", at("2026-08-11T00:00:00Z"))
            current = json.loads(path.read_text(encoding="utf-8"))
            preserved = json.loads(backup.read_text(encoding="utf-8"))
            self.assertEqual(current["health"], "unknown")
            self.assertEqual(preserved["health"], "healthy")


class TransitionTests(unittest.TestCase):
    def setUp(self):
        self.now = at("2026-08-10T00:00:00Z")  # Monday 09:00 KST
        self.state = rg.default_state("boot-a", self.now)
        self.good = rg.CheckResult(True, 1, 49.5)
        self.bad = rg.CheckResult(True, 1, 12.0)

    def test_single_failure_is_degraded_without_notification(self):
        rg.apply_check(self.state, self.bad, self.now, 30, 2)
        self.assertEqual(self.state["health"], "degraded")
        self.assertEqual(self.state["consecutive_failures"], 1)
        self.assertEqual(self.state["current_week"]["failures"], 1)
        self.assertEqual(rg.pending_notifications(self.state, self.now, "host", 12), [])

    def test_second_failure_opens_incident_then_reminds_after_12_hours(self):
        rg.apply_check(self.state, self.bad, self.now, 30, 2)
        rg.apply_check(self.state, self.bad, self.now + timedelta(minutes=15), 30, 2)
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
        rg.apply_check(self.state, self.bad, self.now, 30, 2)
        rg.apply_check(self.state, self.good, self.now + timedelta(minutes=15), 30, 2)
        self.assertEqual(self.state["health"], "healthy")
        self.assertIsNone(self.state["pending_recovery"])

        rg.apply_check(self.state, self.bad, self.now + timedelta(minutes=30), 30, 2)
        rg.apply_check(self.state, self.bad, self.now + timedelta(minutes=45), 30, 2)
        note = rg.pending_notifications(self.state, self.now + timedelta(minutes=45), "host", 12)[0]
        rg.mark_notification_sent(self.state, note, self.now + timedelta(minutes=45))
        rg.apply_check(self.state, self.good, self.now + timedelta(hours=1), 30, 2)
        notes = rg.pending_notifications(self.state, self.now + timedelta(hours=1), "host", 12)
        self.assertEqual([item.kind for item in notes], ["recovery"])
        self.assertEqual(self.state["consecutive_failures"], 0)

    def test_boot_change_resets_only_streak(self):
        rg.apply_check(self.state, self.bad, self.now, 30, 2)
        self.state["last_alert_at"] = rg.utc_text(self.now)
        counters = self.state["current_week"].copy()
        changed = rg.handle_boot_change(self.state, "boot-b")
        self.assertTrue(changed)
        self.assertEqual(self.state["consecutive_failures"], 0)
        self.assertEqual(self.state["last_alert_at"], rg.utc_text(self.now))
        self.assertEqual(self.state["current_week"], counters)

    def test_week_roll_preserves_summary_until_due_and_merges_if_still_pending(self):
        self.state["current_week"].update(checks=10, failures=2, incidents=1)
        next_week_start = self.now + timedelta(days=7) - timedelta(hours=9)
        rg.rotate_week(self.state, next_week_start)
        pending = self.state["pending_weekly"]
        self.assertEqual(pending["checks"], 10)
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


class SentinelIntegrationTests(unittest.TestCase):
    def test_failed_weekly_send_remains_for_next_check(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            now = at("2026-08-10T00:00:00Z")
            state = rg.default_state("boot", now - timedelta(days=7))
            state["current_week"].update(checks=672, failures=2, incidents=1)
            rg.StateStore(path).save(state)
            notifier = FakeNotifier(False)
            settings = rg.Settings(state_file=path)
            sentinel = rg.Sentinel(
                settings,
                rg.StateStore(path),
                FakeProbe(rg.CheckResult(True, 1, 50)),
                notifier,
                "host",
                boot_id_reader=lambda: "boot",
            )
            sentinel.check(now)
            persisted = json.loads(path.read_text(encoding="utf-8"))
            self.assertIsNotNone(persisted["pending_weekly"])
            self.assertEqual(len(notifier.messages), 1)

            notifier.succeeds = True
            sentinel.check(now + timedelta(minutes=15))
            persisted = json.loads(path.read_text(encoding="utf-8"))
            self.assertIsNone(persisted["pending_weekly"])
            self.assertEqual(len(notifier.messages), 2)


class UnitTests(unittest.TestCase):
    def test_service_can_read_boinc_rpc_credentials_without_changing_state_ownership(self):
        unit = (
            Path(__file__).resolve().parents[1] / "systemd" / "sentinel.service"
        ).read_text(encoding="utf-8")
        self.assertIn("User=root\n", unit)
        self.assertIn("Group=root\n", unit)
        self.assertIn("SupplementaryGroups=boinc\n", unit)
        self.assertIn("StateDirectory=sentinel\n", unit)


if __name__ == "__main__":
    unittest.main()
