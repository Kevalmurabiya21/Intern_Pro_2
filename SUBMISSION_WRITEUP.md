# RDRS Reflection

## Design choices

RDRS uses a rules-based scoring engine rather than machine learning. This was intentional: a security alert must be explainable to the person investigating it. Every point in the 0–100 score maps to a named observation, such as rapid file modification, mass extension changes, high file entropy, a CPU spike, or an unknown program. The detector maintains a sliding time window so it can distinguish a burst of ransomware-like activity from isolated file changes.

I also designed the response to be edge-triggered and protected it with an incident cooldown. During stress testing, a noisy score that repeatedly moved between Warning and Critical created 447 duplicate incidents in 90 seconds. The cooldown reduced that result to three incidents by treating a sustained burst as one incident. Response remains simulation-only: evidence is copied to quarantine and the proposed process action is logged, but no original file is deleted and no process is terminated.

## Testing approach

I used unit, integration, and live Windows tests. The automated suite now has 72 tests and 95% coverage. It tests configuration validation, entropy calculation, database persistence, API routes, logging, process monitoring, file-monitor lifecycle, report generation, cooldown handling, and the full detection-to-quarantine workflow. I also ran the dashboard locally on Windows and triggered the safe sandbox simulation; it reached Critical, created one incident, produced JSON/CSV/HTML/PDF reports, and preserved the original files. This work also exposed a Windows performance issue: process enumeration occurred once for each file event. Sampling process state once per second made the burst test complete in seconds rather than minutes.

## False-positive case considered

CPU spike and unknown-program signals can describe a legitimate backup, compiler, or another busy application rather than ransomware. RDRS mitigates this with a configurable CPU threshold and a known-program allow-list. A stronger future design would attribute CPU and I/O to the process actually touching the affected files instead of using whichever process is busiest at the moment.

## Future improvements

The next step is stronger process-to-file attribution, followed by an opt-in—but carefully gated—real response workflow. Multi-host deployment, network-aware monitoring, and long-duration resilience testing would make the tool more operationally useful. Machine-learning anomaly detection could also complement the existing rules, while the rules remain visible so alerts stay explainable.

