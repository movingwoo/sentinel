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
        self.assertEqual(state["schema_version"], rg.SCHEMA_VERSION)
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


def recovery_settings(**overrides):
    return rg.Settings(**overrides)


class RecoveryGateTests(unittest.TestCase):
    def setUp(self):
        self.now = at("2026-09-01T12:00:00Z")
        self.state = rg.default_state("boot", self.now)
        self.state["consecutive_failures"] = 1
        self.settings = recovery_settings()

    def block(self, result, **overrides):
        settings = recovery_settings(**overrides) if overrides else self.settings
        return rg.recovery_block_reason(self.state, result, settings, self.now)

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
        self.state["recoveries_this_incident"] = 2
        self.assertEqual(
            self.block(rg.CheckResult(True, 0, 0.0)), "incident budget spent 2/2"
        )

    def test_cooldown_blocks_and_then_expires(self):
        self.state["last_recovery_at"] = rg.utc_text(self.now - timedelta(hours=2))
        reason = self.block(rg.CheckResult(True, 0, 0.0))
        self.assertIsNotNone(reason)
        self.assertTrue(reason.startswith("cooldown for another 4.0h"), reason)

        self.state["last_recovery_at"] = rg.utc_text(self.now - timedelta(hours=6, minutes=1))
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


class RecoveryIntegrationTests(unittest.TestCase):
    def build(self, path, probe_result, recovery, **overrides):
        settings = rg.Settings(state_file=path, **overrides)
        notifier = FakeNotifier(True)
        sentinel = rg.Sentinel(
            settings,
            rg.StateStore(path),
            FakeProbe(probe_result),
            notifier,
            "host",
            boot_id_reader=lambda: "boot",
            recovery=recovery,
        )
        return sentinel, notifier

    def test_starvation_syncs_once_then_the_cooldown_holds_the_line(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            now = at("2026-09-01T12:00:00Z")
            recovery = FakeRecovery()
            sentinel, notifier = self.build(path, rg.CheckResult(True, 0, 0.0), recovery)

            sentinel.check(now)
            persisted = json.loads(path.read_text(encoding="utf-8"))
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
            persisted = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["recoveries_this_incident"], 1)

    def test_cooldown_expiry_allows_a_second_attempt_then_the_budget_stops_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            now = at("2026-09-01T12:00:00Z")
            recovery = FakeRecovery()
            sentinel, _ = self.build(path, rg.CheckResult(True, 0, 0.0), recovery)

            sentinel.check(now)
            sentinel.check(now + timedelta(hours=7))
            self.assertEqual(recovery.calls, 2)
            sentinel.check(now + timedelta(hours=14))
            self.assertEqual(recovery.calls, 2, "incident budget must cap the attempts")
            persisted = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["recoveries_this_incident"], 2)

    def test_recovering_resets_the_budget_but_keeps_the_global_cooldown(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            now = at("2026-09-01T12:00:00Z")
            recovery = FakeRecovery()
            sentinel, _ = self.build(path, rg.CheckResult(True, 0, 0.0), recovery)
            sentinel.check(now)

            healthy, _ = self.build(path, rg.CheckResult(True, 1, 50.0), recovery)
            healthy.check(now + timedelta(minutes=15))
            persisted = json.loads(path.read_text(encoding="utf-8"))
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
            sentinel, _ = self.build(path, rg.CheckResult(True, 0, 0.0), recovery)

            with self.assertRaises(RuntimeError):
                sentinel.check(now)

            persisted = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["last_recovery_at"], rg.utc_text(now))
            self.assertEqual(persisted["recoveries_this_incident"], 1)

    def test_failed_sync_is_reported_and_still_costs_an_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            now = at("2026-09-01T12:00:00Z")
            recovery = FakeRecovery(result=(False, "acct_mgr sync exit 1"))
            sentinel, notifier = self.build(path, rg.CheckResult(True, 0, 0.0), recovery)

            sentinel.check(now)
            persisted = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["recoveries_this_incident"], 1)
            self.assertIn("자동복구 실패", notifier.messages[0])
            self.assertIn("acct_mgr sync exit 1", notifier.messages[0])

    def test_undelivered_recovery_alert_survives_for_the_next_check(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            now = at("2026-09-01T12:00:00Z")
            recovery = FakeRecovery()
            settings = rg.Settings(state_file=path)
            notifier = FakeNotifier(False)
            sentinel = rg.Sentinel(
                settings,
                rg.StateStore(path),
                FakeProbe(rg.CheckResult(True, 0, 0.0)),
                notifier,
                "host",
                boot_id_reader=lambda: "boot",
                recovery=recovery,
            )
            sentinel.check(now)
            persisted = json.loads(path.read_text(encoding="utf-8"))
            self.assertIsNotNone(persisted["pending_recovery_alert"])
            self.assertEqual(persisted["pending_recovery_alert"]["attempt"], 1)


class RecoveryMigrationTests(unittest.TestCase):
    def test_schema_one_state_gains_recovery_fields_without_losing_history(self):
        raw = rg.default_state("boot", at("2026-08-10T00:00:00Z"))
        raw["schema_version"] = 1
        raw["health"] = "unhealthy"
        raw["consecutive_failures"] = 99
        raw["incident_started_at"] = "2026-09-01T08:30:00Z"
        raw["incident_confirmed"] = True
        raw["incident_alert_sent"] = True
        raw["last_alert_at"] = "2026-09-02T08:45:00Z"
        raw["current_week"].update(checks=265, failures=99, incidents=1)
        for key in ("pending_recovery_alert", "last_recovery_at", "recoveries_this_incident"):
            del raw[key]

        state = rg.migrate_state(raw, "boot", at("2026-09-02T09:00:00Z"))

        self.assertEqual(state["schema_version"], rg.SCHEMA_VERSION)
        self.assertEqual(state["consecutive_failures"], 99)
        self.assertEqual(state["current_week"]["checks"], 265)
        self.assertIsNone(state["last_recovery_at"])
        self.assertIsNone(state["pending_recovery_alert"])
        self.assertEqual(state["recoveries_this_incident"], 0)


if __name__ == "__main__":
    unittest.main()
