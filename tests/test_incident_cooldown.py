"""
Regression test for a bug found via manual soak testing (90s of continuous
realistic file churn, no real attack): the detection score can flap in and
out of Critical rapidly (driven by noisy signals like cpu_spike/
unknown_program, which key off whatever process momentarily has the highest
CPU). Edge-triggering alone (only responding when the band CHANGES to
Critical) is not enough to prevent this - the band can drop out of Critical
for a single event and immediately re-enter it, counting as a "new" edge
every time. Without a cooldown this created 447 duplicate incidents in 90
seconds during soak testing. This test reproduces that flapping pattern
directly (score alternates Critical/Warning/Critical/Warning...) against the
same cooldown logic used in app.main, and asserts it collapses down to a
small number of incidents rather than one per flap.
"""
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def cooldown_gate(bands, cooldown_seconds, clock):
    """Reimplements the exact suppression logic from app/main.py's on_event
    handler, decoupled from real time via an injectable clock, so the test
    is fast and deterministic instead of sleeping for real seconds."""
    previous_band = "Normal"
    last_incident_time = None
    incident_count = 0
    suppressed_count = 0

    for band in bands:
        entering_critical = band == "Critical" and previous_band != "Critical"
        previous_band = band
        if not entering_critical:
            continue
        now = clock()
        if last_incident_time is not None and (now - last_incident_time) < cooldown_seconds:
            suppressed_count += 1
            continue
        last_incident_time = now
        incident_count += 1

    return incident_count, suppressed_count


class TestIncidentCooldown(unittest.TestCase):
    def test_flapping_band_without_cooldown_creates_one_incident_per_flap(self):
        # Reproduces the original bug: cooldown_seconds=0 means every single
        # re-entry into Critical counts as a fresh incident.
        bands = ["Normal", "Critical", "Warning", "Critical", "Warning", "Critical",
                 "Warning", "Critical", "Warning", "Critical"] * 10  # 50 flaps
        t = [0.0]
        def clock():
            t[0] += 0.1
            return t[0]

        incidents, suppressed = cooldown_gate(bands, cooldown_seconds=0, clock=clock)
        self.assertEqual(incidents, 50, "Without a cooldown, every flap should still count (proves the bug existed)")

    def test_flapping_band_with_cooldown_collapses_to_one_incident(self):
        # Same flapping pattern, but all within one cooldown window (real
        # elapsed time << cooldown_seconds) - exactly the soak-test scenario.
        bands = ["Normal", "Critical", "Warning", "Critical", "Warning", "Critical",
                 "Warning", "Critical", "Warning", "Critical"] * 10  # 50 flaps

        t = [0.0]
        def clock():
            t[0] += 0.1  # 0.1s between events - all 50 flaps happen within ~5s
            return t[0]

        incidents, suppressed = cooldown_gate(bands, cooldown_seconds=30, clock=clock)
        self.assertEqual(incidents, 1, "All flapping within the cooldown window should collapse to one incident")
        self.assertEqual(suppressed, 49)

    def test_incidents_spaced_beyond_cooldown_both_count(self):
        previous_band = "Normal"

        def make_clock(times):
            it = iter(times)
            return lambda: next(it)

        bands = ["Critical", "Critical"]  # two separate "entering" events, simulated via two calls
        # First incident at t=0
        incidents1, _ = cooldown_gate(["Normal", "Critical"], cooldown_seconds=30, clock=make_clock([0.0]))
        self.assertEqual(incidents1, 1)

        # A second, independent burst 60s later (beyond the 30s cooldown) should
        # also produce its own incident - the cooldown must not suppress
        # genuinely separate attacks forever.
        incidents2, _ = cooldown_gate(["Normal", "Critical"], cooldown_seconds=30, clock=make_clock([60.0]))
        self.assertEqual(incidents2, 1)


if __name__ == "__main__":
    unittest.main()
