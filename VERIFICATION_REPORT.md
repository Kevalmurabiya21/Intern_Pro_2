# RDRS Verification Report

Date: 29 September 2026  
Host: Windows, Python 3.14.4

| Check | Result |
| --- | --- |
| `pip install -r requirements.txt` | Passed; dependency check reports no conflicts. |
| Automated tests | Passed: 72 tests. |
| Coverage | Passed: 95% overall. |
| Windows local run | Passed: dashboard served on `http://127.0.0.1:8000/dashboard`; safe simulation reached Critical (score 100), created one incident, and generated all four report formats. |
| Docker build/run | Passed: WSL was enabled, Docker Desktop started, and the image built successfully. The container became healthy; an in-container staged safe simulation reached Critical (score 95), created incident #2, copied 10 evidence files to quarantine, and generated JSON/CSV/HTML/PDF reports. |

The project now samples system processes at most once per second during a file-event burst. This retains the process signal while avoiding costly process enumeration on every filesystem event, which was particularly slow on Windows. Docker Compose also enables polling for the file monitor so Docker Desktop bind mounts are detected reliably.

Generated runtime evidence is available in `data/reports/`, `logs/`, and `submission_evidence/`.
