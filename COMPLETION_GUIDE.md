# RDRS Completion Guide - Detailed Step-by-Step

This is the complete, detailed walkthrough for finishing the RDRS project on
your own machine. Follow it in order - each step assumes the previous one is
done. Commands shown are for macOS/Linux; Windows equivalents are noted
where they differ.

---

## STEP 1: Get the project onto your machine

### 1.1 Download and unzip
1. Download `RDRS_project.zip` from the chat.
2. Move it somewhere sensible, e.g. `~/projects/`.
3. Unzip it:
   ```bash
   cd ~/projects
   unzip RDRS_project.zip
   cd rdrs
   ```
   On Windows: right-click the zip → "Extract All", then open the `rdrs`
   folder in a terminal (or `cd rdrs` in PowerShell/CMD).

### 1.2 Confirm Python version
```bash
python --version
```
or on some systems:
```bash
python3 --version
```
You need **3.12 or higher**. If you're below that:
- macOS: `brew install python@3.12`
- Windows: download from https://python.org/downloads (check "Add to PATH" during install)
- Linux: `sudo apt install python3.12` (Ubuntu/Debian) or use `pyenv`

### 1.3 Look at what you have
```bash
ls -la
```
You should see: `app/`, `tests/`, `scripts/`, `config.yaml`, `requirements.txt`,
`README.md`, `Dockerfile`, `docker-compose.yml`, `.gitignore`, `data/`, `logs/`.

If anything is missing, re-download the zip - something went wrong in extraction.

---

## STEP 2: Verify it runs as-is (zero extra installs)

This build works out of the box with just the standard library plus
`watchdog`, `psutil`, `pyyaml`, `jinja2`, `reportlab` - libraries that were
already available when I tested it. Confirm that's true on your machine too
before moving to the "official" stack.

### 2.1 Check the light dependencies are present
```bash
python -c "import watchdog, psutil, yaml, jinja2, reportlab; print('all present')"
```
If this fails with `ModuleNotFoundError`, install just those five:
```bash
pip install watchdog psutil pyyaml jinja2 reportlab
```

### 2.2 Run the monitor
Open a terminal in the `rdrs` folder and run:
```bash
python -m app.main --auto-report
```
**Expected output**, roughly:
```
2026-XX-XX ... | INFO | rdrs.system | ============================================================
2026-XX-XX ... | INFO | rdrs.system | RDRS starting up
2026-XX-XX ... | INFO | rdrs.system | Watching: ['./data/sandbox']
2026-XX-XX ... | INFO | rdrs.system | Simulation mode: True
2026-XX-XX ... | INFO | rdrs.system | ============================================================
2026-XX-XX ... | INFO | rdrs.system | FileMonitor watching: /path/to/rdrs/data/sandbox
2026-XX-XX ... | INFO | rdrs.system | API listening on http://127.0.0.1:8000  (try /health, /status, /alerts)
2026-XX-XX ... | INFO | rdrs.system | Dashboard: http://127.0.0.1:8000/dashboard
2026-XX-XX ... | INFO | rdrs.system | RDRS is running. Press Ctrl+C to stop.
```
**Leave this terminal running.** Don't press Ctrl+C yet.

If you see `Address already in use`, something else is using port 8000 -
either stop it, or run with a different port by editing `config.yaml`'s
`api.port` value.

### 2.3 Open the dashboard
In your browser, go to: **http://127.0.0.1:8000/dashboard**

You should see a dark-themed page with:
- "Current Threat Level" showing **NORMAL** in green
- Score bar near 0
- Empty "Recent Alerts" and "Recent Events" tables

Leave this tab open - it auto-refreshes every 3 seconds.

### 2.4 Trigger the safe simulated attack
Open a **second terminal** (don't close the first one), `cd` into the same
`rdrs` folder, and run:
```bash
python scripts/sandbox_attack_sim.py
```
**Expected output:**
```
[1/2] Creating 50 normal files in data/sandbox/ ...
[2/2] Simulating an attack: overwrite with random bytes + rename to .locked ...
Done. Check the monitor output / dashboard / logs/alerts.log for a Critical detection.
```

### 2.5 Watch it detect
Within a few seconds:
- The **dashboard** should flip to **CRITICAL** in red, pulsing, with the score bar near 100
- "Fired signals" should list things like `rapid_encryption, mass_rename, high_entropy`
- "Recent Alerts" should show a row with band=Critical
- The first terminal (still running `app.main`) should print lines like:
  ```
  ... | WARNING | rdrs.alerts | Critical band | score=100 | signals=[...]
  ... | INFO    | rdrs.audit  | CRITICAL response | suspect=... | quarantined 50 file(s) | originals untouched
  ... | INFO    | rdrs.audit  | SIMULATION MODE: would terminate pid=... - no process was actually killed.
  ... | WARNING | rdrs.alerts | Incident #1 created | score=100 | 50 affected file(s)
  ```

### 2.6 Check the generated reports
```bash
ls data/reports/
```
You should see 4 files: `incident_1.json`, `incident_1.csv`, `incident_1.html`,
`incident_1.pdf`. Open the `.html` one in a browser or the `.pdf` in any PDF
viewer to see the formatted incident report.

### 2.7 Check quarantine and originals
```bash
ls data/quarantine/     # should contain ~50 copied files
ls data/sandbox/        # originals should still be there, renamed to .locked
```
This proves originals were never deleted - only copied.

### 2.8 Stop the monitor
Go back to the first terminal and press **Ctrl+C**. You should see:
```
... | INFO | rdrs.system | Shutting down RDRS...
```
and it exits cleanly.

**✅ If all of 2.2-2.8 worked, the core project is proven functional on your
machine.** If something failed, note the exact error message before
continuing - it'll help diagnose whether it's an environment difference.

---

## STEP 3: Run the automated test suite

### 3.1 Run it with stdlib unittest (no installs needed)
```bash
python -m unittest discover -s tests -v
```
**Expected**: `Ran 56 tests in ~3s` and `OK` at the bottom, with every test
line ending in `ok`. If any say `FAIL` or `ERROR`, copy the full traceback -
that's a real problem to fix, not something to ignore.

### 3.2 Install the "official" library stack
This installs FastAPI, SQLAlchemy, pydantic, loguru, pytest, uvicorn, httpx -
the libraries the original build guide named, which I could never test
against directly (no internet in my sandbox).
```bash
pip install -r requirements.txt
```
Watch for errors. If a specific package fails, note which one and try
installing it alone to see the real error:
```bash
pip install fastapi
```

### 3.3 Re-run tests with pytest
```bash
pytest -v
```
This runs the exact same 56 tests through pytest instead of `unittest` -
they're written in a way that both runners understand. Confirm the same
count passes.

### 3.4 (Optional) Swap in the "official" libraries
The current code works correctly using stdlib equivalents. If your grading
specifically checks for FastAPI/SQLAlchemy/pydantic/loguru by name in the
code, here's exactly what to touch - each is fully isolated, so nothing else
in the app needs to change:

| To swap | Edit only this file | What changes |
|---|---|---|
| Config → pydantic | `app/core/config.py` | Replace `@dataclass` classes with `pydantic.BaseModel` subclasses |
| Logging → loguru | `app/core/logging_setup.py` | Replace `logging.getLogger`/`RotatingFileHandler` with `loguru.logger.add(...)` sinks |
| Database → SQLAlchemy | `app/database/db.py` | Replace raw `sqlite3` calls with SQLAlchemy `Table`/`Session` |
| API → FastAPI | `app/api/server.py` | Replace `http.server.BaseHTTPRequestHandler` routes with `@app.get`/`@app.post` decorators, run via `uvicorn.run(app, ...)` |

This is genuinely optional - do it only if required. It's real, careful work
(a few hours), not a find-and-replace.

---

## STEP 4: Build and run Docker (never verified - do this carefully)

### 4.1 Confirm Docker is installed and running
```bash
docker --version
docker compose version
```
If these fail, install Docker Desktop (Mac/Windows) or Docker Engine (Linux)
from https://docs.docker.com/get-docker/, then make sure the Docker
application/daemon is actually running (there's usually a whale icon in your
system tray/menu bar when it's up).

### 4.2 Build and start
From the `rdrs` folder:
```bash
docker compose up
```
The first run will take a minute or two - it downloads the `python:3.12-slim`
base image and installs `requirements.txt` for real (with actual internet
access this time). Watch the build log for errors, especially around
`pip install`.

**Common issues to watch for:**
- `permission denied` on Linux → you may need `sudo docker compose up`, or add your user to the `docker` group
- Port 8000 already bound → stop whatever else is using it, or change the port mapping in `docker-compose.yml` (the `"8000:8000"` line)
- Build fails installing a package → note the exact package and error

### 4.3 Verify it works
Once you see something like `Uvicorn running` or the RDRS startup banner in
the container logs, open **http://localhost:8000/dashboard** in your browser.

### 4.4 Test detection inside the container
The sandbox attack script needs to write into the *same* `data/sandbox`
folder the container is watching. Since `docker-compose.yml` mounts `./data`
from your host into the container, you can trigger it from your host machine
directly, in a second terminal:
```bash
python scripts/sandbox_attack_sim.py
```
Then check the dashboard again for CRITICAL, exactly as in Step 2.5.

### 4.5 Stop it
```bash
docker compose down
```
Your `data/` and `logs/` folders persist on the host (check `docker-compose.yml` -
they're mounted, not container-only), so you can inspect the results afterward.

### 4.6 Record the outcome
Whatever happens - success or specific errors - write it down. This is
genuinely unverified territory from my side, so your notes here matter for
the write-up (Step 7) and for fixing anything that breaks.

---

## STEP 5: Push test coverage higher (optional, recommended)

### 5.1 Measure current coverage properly
```bash
pip install pytest-cov   # if not already installed via requirements.txt
pytest --cov=app --cov-report=term-missing
```
This prints a table showing % covered per file and the exact line numbers
still missing coverage.

### 5.2 Target the weakest modules first
Based on my own testing, these need the most attention:
- `app/core/logging_setup.py` (~19% covered) - hard to test because it's mostly file-handler wiring; you could test that `setup_logging()` actually creates the 5 log files and that messages land in the right one.
- `app/detectors/process_monitor.py` (~44%) - test `find_process()` with a known PID (e.g. your own process via `os.getpid()`), and `snapshot_processes(top_n_by_cpu=N)` returns at most N results.
- `app/detectors/file_monitor.py` (~52%) - test that `FileMonitor.stop()` actually stops watching (no more events after stop).

### 5.3 Write a new test file per module
Follow the existing pattern in `tests/` - e.g. create `tests/test_logging.py`:
```python
import sys, tempfile, shutil, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.core.config import load_settings
from app.core.logging_setup import setup_logging, get_logger

class TestLogging(unittest.TestCase):
    def test_five_log_files_are_created(self):
        tmpdir = Path(tempfile.mkdtemp())
        try:
            settings = load_settings("config.yaml")
            settings.logging.dir = str(tmpdir)
            setup_logging(settings)
            get_logger("system").info("test message")
            self.assertTrue((tmpdir / "system.log").exists())
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

if __name__ == "__main__":
    unittest.main()
```
Run `pytest --cov=app --cov-report=term-missing` again afterward to confirm
the number went up.

---

## STEP 6: Capture your demo evidence

### 6.1 Screenshots to take
1. The dashboard in **NORMAL** state (green, score near 0)
2. The dashboard in **CRITICAL** state (red, pulsing, score near 100, fired signals listed)
3. Terminal output showing the detection log lines (the `CRITICAL response`/`Incident #1 created` lines)
4. `data/reports/` folder listing showing the 4 generated files
5. The opened PDF or HTML report

### 6.2 Screen recording (optional but stronger)
Record ~60-90 seconds: start the monitor, show the dashboard at Normal, run
the attack script in a second terminal, watch the dashboard flip to
Critical in real time. Screen recording tools: QuickTime (Mac, built-in),
Xbox Game Bar (Windows, Win+G), or OBS Studio (free, cross-platform).

### 6.3 Save the raw evidence files
Copy (don't just screenshot) the actual files so you can attach them:
```bash
mkdir submission_evidence
cp -r data/reports submission_evidence/
cp logs/alerts.log logs/audit.log submission_evidence/
```

---

## STEP 7: Write the one-page write-up

Structure it around these four required sections (from the grading rubric):

**1. Design choices**
- Rule-based scoring (not ML) - explainable, no training data needed, every point traceable to a named signal
- Sliding-window approach for burst detection
- Edge-triggered response + cooldown (mention the 447→3 incident bug you can reference from the README's "Stress testing performed" section - this is real, specific material)
- Simulation-mode-only response as a deliberate safety choice, not just a config flag

**2. Testing approach**
- 56 automated tests (unit + integration), ~65% coverage
- Manual stress testing: malformed config, permission failures, 500MB files, unicode filenames, 18-thread concurrency, 90-second soak test
- Mention the 3 real bugs found and fixed this way (README has the full table)

**3. A false-positive case considered**
Use the one already documented in the README: `cpu_spike`/`unknown_program`
firing on whatever process happens to have the highest CPU at that instant -
which can be a legitimate backup job or compiler, not an attack. Explain how
`config.yaml`'s `known_programs` allow-list and `cpu_spike_percent`
threshold mitigate this, and that attributing CPU usage to the process
*actually touching the affected files* (rather than just "highest CPU right
now") would be a stronger fix.

**4. Future improvements**
- Attribute CPU/IO to the specific process touching affected files, not just system-wide highest-CPU
- Push test coverage further (Step 5)
- Add real process-termination as an opt-in, carefully gated feature (currently hard-disabled by design)
- Multi-host/network deployment support
- Machine-learning-assisted anomaly detection as a complement to the rule engine (not a replacement, to keep explainability)

Keep it to one page - this is a reflection, not documentation (the README
already covers documentation).

---

## STEP 8: Set up Git and submit

### 8.1 Initialize the repo
```bash
git init
git add .
git status
```
Check the output of `git status` - it should **not** list `data/rdrs.db`,
`logs/*.log`, or files inside `data/sandbox`/`data/quarantine`/`data/reports`
(the `.gitignore` already excludes these). If it does list them, don't
commit yet - fix `.gitignore` first.

### 8.2 Commit
```bash
git commit -m "RDRS - Ransomware Detection and Response System"
```

### 8.3 Create a remote repo and push
On GitHub (or GitLab/etc.):
1. Create a new empty repository (don't initialize with a README - you already have one)
2. Copy the remote URL it gives you
3. Back in your terminal:
   ```bash
   git remote add origin <the-url-you-copied>
   git branch -M main
   git push -u origin main
   ```

### 8.4 Double-check the pushed repo
Open the repo page in your browser and confirm:
- The README renders with proper formatting
- `data/`, `logs/` folders only show the `.gitkeep` placeholders, not real runtime data
- All source files are present

### 8.5 Final submission checklist
Cross-check against the submission checklist from earlier: git repo ✅,
architecture overview (README has one) ✅, demo screenshots/recording (Step 6)
✅, sample report + logs (Step 6.3) ✅, one-page write-up (Step 7) ✅.

---

## If something goes wrong

- **Step 2 fails** (core app won't run at all): this is the most important
  one to fix first - it means something in your Python environment differs
  from what I tested. Share the exact error and we can debug it together.
- **Step 3 fails** (tests fail after `pip install -r requirements.txt`):
  likely a version mismatch between installed packages - check with
  `pip list` and compare against the versions in `requirements.txt`.
- **Step 4 fails** (Docker): this is genuinely new territory - take notes on
  the exact error and we can work through it.
- **Steps 5-8**: these are yours to do at your own pace - no wrong way to do
  them as long as the end result is a working, documented, submittable project.
