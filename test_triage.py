import json
import subprocess
import sys
import unittest
from pathlib import Path

from triage import analyze


def event(timestamp, outcome="failure", source="192.0.2.10", **extra):
    return json.dumps(dict(timestamp=timestamp, source_ip=source, outcome=outcome, **extra))


class TriageTests(unittest.TestCase):
    def test_boundary_is_inclusive_but_later_event_is_outside(self):
        lines = [event("2026-01-01T10:00:00Z"), event("2026-01-01T10:05:00Z")]
        self.assertEqual(len(analyze(lines, 2, 300)["findings"]), 1)
        lines[1] = event("2026-01-01T10:05:01Z")
        self.assertEqual(analyze(lines, 2, 300)["findings"], [])

    def test_unsorted_events_and_offsets_represent_same_time(self):
        report = analyze(
            [
                event("2026-01-01T10:01:00Z"),
                event("2026-01-01T07:00:00-03:00"),
            ],
            2,
            60,
        )
        self.assertEqual(report["findings"][0]["failures_in_window"], 2)

    def test_successes_and_different_sources_do_not_trigger_rule(self):
        report = analyze(
            [
                event("2026-01-01T10:00:00Z"),
                event("2026-01-01T10:00:10Z", "success"),
                event("2026-01-01T10:00:20Z", source="192.0.2.20"),
            ],
            2,
        )
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["successes"], 1)

    def test_bad_records_are_counted_without_echoing_contents(self):
        lines = [
            "",
            "not json",
            "[]",
            event("2026-01-01T10:00:00"),
            event("2026-01-01T10:00:00Z", source="invalid"),
            event("2026-01-01T10:00:00Z", password="do-not-echo"),
        ]
        report = analyze(lines)
        self.assertEqual(report["invalid_line_numbers"], [2, 3, 4, 5])
        self.assertEqual(report["valid_events"], 1)
        self.assertNotIn("do-not-echo", json.dumps(report))

    def test_ipv6_addresses_are_normalized_and_grouped(self):
        report = analyze(
            [
                event("2026-01-01T10:00:00Z", source="2001:db8::1"),
                event("2026-01-01T10:00:01Z", source="2001:0db8:0:0:0:0:0:1"),
            ],
            2,
        )
        self.assertEqual(report["findings"][0]["source_ip"], "2001:db8::1")

    def test_one_finding_per_ip_and_empty_input(self):
        lines = [event(f"2026-01-01T10:00:0{i}Z") for i in range(8)]
        self.assertEqual(len(analyze(lines)["findings"]), 1)
        self.assertEqual(analyze([])["valid_events"], 0)

    def test_invalid_configuration(self):
        with self.assertRaises(ValueError):
            analyze([], threshold=1)
        with self.assertRaises(ValueError):
            analyze([], window_seconds=0)

    def test_cli_example_and_missing_input(self):
        root = Path(__file__).parent
        result = subprocess.run(
            [sys.executable, str(root / "triage.py"), str(root / "examples/auth.jsonl")],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)["findings"]), 1)
        result = subprocess.run(
            [sys.executable, str(root / "triage.py"), str(root / "examples/does-not-exist.jsonl")],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        result = subprocess.run(
            [
                sys.executable,
                str(root / "triage.py"),
                str(root / "examples/auth.jsonl"),
                "--window-seconds",
                "999999999999999999999",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
