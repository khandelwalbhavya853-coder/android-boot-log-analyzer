import unittest

from boot_analyzer import analyze_lines, render_html


class AnalyzeLinesTests(unittest.TestCase):
    def test_classifies_known_boot_issues_and_calculates_time(self):
        report = analyze_lines([
            "[    0.000000] Linux boot",
            "[    1.000000] wlan: Direct firmware load for wifi.bin failed with error -2",
            '[    2.000000] audit(0.0:1): avc: denied { read } for name="calibration"',
            "[   42.000000] Boot completed",
        ])
        self.assertEqual(report["total_boot_time_seconds"], 42.0)
        self.assertEqual(report["issue_count"], 2)
        self.assertEqual(report["issue_counts_by_category"], {"Firmware": 1, "SELinux": 1})

    def test_finds_slow_init_action(self):
        report = analyze_lines(["[ 1.0] init: processing action (late-fs) took 1500ms"])
        self.assertEqual(len(report["slow_stages"]), 1)
        self.assertIn("slow initialization stages", render_html(report).lower())

    def test_missing_timestamps_are_reported(self):
        report = analyze_lines(["E AndroidRuntime: FATAL EXCEPTION: main"])
        self.assertIsNone(report["total_boot_time_seconds"])
        self.assertTrue(report["notes"])
        self.assertEqual(report["issues"][0]["severity"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()
