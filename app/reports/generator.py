"""
Phase 8: Reporting.

Produces an incident report from a stored incident record: a timeline of
events, the threat score, affected files, the suspect process, and basic
recommendations. JSON and CSV are always generated (required); HTML and PDF
are generated too since jinja2 and reportlab are available in this build.
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from jinja2 import Template
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

from app.database import db

_HTML_TEMPLATE = Template("""
<!DOCTYPE html><html><head><meta charset="utf-8">
<title>RDRS Incident Report #{{ incident.id }}</title>
<style>
  body { font-family: -apple-system, Arial, sans-serif; margin: 40px; color:#1a1a1a; }
  h1 { border-bottom: 3px solid #{{ band_color }}; padding-bottom: 8px; }
  .badge { display:inline-block; padding:4px 12px; border-radius:6px; color:white;
           background:#{{ band_color }}; font-weight:bold; }
  table { border-collapse: collapse; width:100%; margin: 16px 0; }
  th, td { border: 1px solid #ccc; padding: 6px 10px; text-align:left; font-size: 13px; }
  th { background: #f0f0f0; }
  .rec { background:#f7f7f7; border-left:4px solid #{{ band_color }}; padding:12px; margin-top:20px;}
</style></head>
<body>
  <h1>RDRS Incident Report #{{ incident.id }}</h1>
  <p><span class="badge">{{ incident.band }} - score {{ incident.score }}</span></p>
  <p><b>Created:</b> {{ incident.created_at }}<br>
     <b>Suspect process:</b> {{ incident.suspect_process }} (pid {{ incident.suspect_pid }})<br>
     <b>Response mode:</b> {{ "Simulation (no process killed)" if incident.simulated_response else "Live" }}</p>

  <h3>Affected files ({{ incident.affected_files|length }})</h3>
  <table><tr><th>#</th><th>Path</th></tr>
  {% for f in incident.affected_files %}<tr><td>{{ loop.index }}</td><td>{{ f }}</td></tr>{% endfor %}
  </table>

  <h3>Evidence quarantined ({{ incident.quarantine_paths|length }})</h3>
  <table><tr><th>#</th><th>Quarantine path</th></tr>
  {% for f in incident.quarantine_paths %}<tr><td>{{ loop.index }}</td><td>{{ f }}</td></tr>{% endfor %}
  </table>

  <div class="rec">
    <b>Recommendations</b>
    <ul>
      <li>Isolate the host from the network until the suspect process has been investigated.</li>
      <li>Preserve the quarantined evidence copies for forensic analysis - do not restore originals yet.</li>
      <li>Check the affected files against known-good backups before any recovery.</li>
      <li>Review whether the suspect process is a legitimate program that should be added to the known-programs allow-list, to reduce future false positives.</li>
    </ul>
  </div>
</body></html>
""")

_BAND_COLORS = {"Normal": "3fb950", "Warning": "d29922", "Critical": "f85149"}


def _reports_dir() -> Path:
    d = Path("data/reports")
    d.mkdir(parents=True, exist_ok=True)
    return d


def generate_json_report(incident_id: int) -> Path:
    incident = db.get_incident(incident_id)
    if incident is None:
        raise ValueError(f"No incident with id {incident_id}")
    out = _reports_dir() / f"incident_{incident_id}.json"
    out.write_text(json.dumps(incident, indent=2, default=str), encoding="utf-8")
    return out


def generate_csv_report(incident_id: int) -> Path:
    incident = db.get_incident(incident_id)
    if incident is None:
        raise ValueError(f"No incident with id {incident_id}")
    out = _reports_dir() / f"incident_{incident_id}.csv"

    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["field", "value"])
        for key in ("id", "created_at", "score", "band", "suspect_process",
                    "suspect_pid", "simulated_response"):
            writer.writerow([key, incident[key]])
        writer.writerow([])
        writer.writerow(["affected_file"])
        for path in incident["affected_files"]:
            writer.writerow([path])
        writer.writerow([])
        writer.writerow(["quarantine_path"])
        for path in incident["quarantine_paths"]:
            writer.writerow([path])
    return out


def generate_html_report(incident_id: int) -> Path:
    incident = db.get_incident(incident_id)
    if incident is None:
        raise ValueError(f"No incident with id {incident_id}")
    out = _reports_dir() / f"incident_{incident_id}.html"
    html = _HTML_TEMPLATE.render(incident=incident, band_color=_BAND_COLORS.get(incident["band"], "888888"))
    out.write_text(html, encoding="utf-8")
    return out


def generate_pdf_report(incident_id: int) -> Path:
    incident = db.get_incident(incident_id)
    if incident is None:
        raise ValueError(f"No incident with id {incident_id}")
    out = _reports_dir() / f"incident_{incident_id}.pdf"

    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(out), pagesize=LETTER,
                             topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    story = [
        Paragraph(f"RDRS Incident Report #{incident['id']}", styles["Title"]),
        Paragraph(f"Band: {incident['band']} &nbsp;&nbsp; Score: {incident['score']}", styles["Heading2"]),
        Paragraph(f"Created: {incident['created_at']}", styles["Normal"]),
        Paragraph(f"Suspect process: {incident['suspect_process']} (pid {incident['suspect_pid']})", styles["Normal"]),
        Paragraph(f"Response mode: {'Simulation' if incident['simulated_response'] else 'Live'}", styles["Normal"]),
        Spacer(1, 16),
        Paragraph(f"Affected files ({len(incident['affected_files'])})", styles["Heading3"]),
    ]

    affected = incident["affected_files"][:40]  # cap for a readable PDF
    if affected:
        data = [["#", "Path"]] + [[str(i + 1), p] for i, p in enumerate(affected)]
        t = Table(data, colWidths=[30, 460])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f0f0")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        story.append(t)
        if len(incident["affected_files"]) > 40:
            story.append(Paragraph(f"... and {len(incident['affected_files']) - 40} more", styles["Normal"]))

    story.append(Spacer(1, 16))
    story.append(Paragraph("Recommendations", styles["Heading3"]))
    for rec in [
        "Isolate the host from the network until the suspect process has been investigated.",
        "Preserve the quarantined evidence copies for forensic analysis.",
        "Check affected files against known-good backups before any recovery.",
        "Review whether the suspect process should be added to the known-programs allow-list.",
    ]:
        story.append(Paragraph(f"&bull; {rec}", styles["Normal"]))

    doc.build(story)
    return out


def generate_all_reports(incident_id: int) -> dict:
    """Generate JSON + CSV (required) and HTML + PDF (bonus) for one incident."""
    return {
        "json": str(generate_json_report(incident_id)),
        "csv": str(generate_csv_report(incident_id)),
        "html": str(generate_html_report(incident_id)),
        "pdf": str(generate_pdf_report(incident_id)),
    }
