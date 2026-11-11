"""Self-contained Huawei review reports, with incomplete coverage made visible."""
import csv
import html
import json
from pathlib import Path

from .review import SEVERITIES

COLUMNS = ("severity", "service", "tier", "check_id", "resource_type", "resource_id", "profile", "account_id",
           "agency_urn", "region", "project_id", "created_time", "title", "recommendation", "detail")


def to_csv(result, path):
    def safe(value):
        text = "" if value is None else str(value)
        return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")) else text
    with open(path, "w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=COLUMNS)
        writer.writeheader()
        for finding in result.details.get("findings", []):
            row = {key: safe(finding.get(key)) for key in COLUMNS}
            row["detail"] = json.dumps(finding.get("detail", {}), sort_keys=True)
            writer.writerow(row)


def to_html(result, path):
    esc = lambda value: html.escape(str(value) if value is not None else "", quote=True)
    details = result.details
    def options(values):
        return '<option value="">All</option>' + "".join(f'<option>{esc(value)}</option>' for value in values)
    rows = []
    for finding in details.get("findings", []):
        rows.append('<tr ' + " ".join(f'data-{key}="{esc(finding.get(key))}"' for key in ("severity", "service", "profile")) + '>'
            + "".join(f'<td>{esc(finding.get(key))}</td>' for key in ("severity", "service", "check_id", "resource_id", "profile", "account_id", "agency_urn", "region", "project_id"))
            + f'<td>{esc(finding.get("title"))}<p>{esc(finding.get("recommendation"))}</p><details><summary>Evidence</summary>'
            + f'<pre>{esc(json.dumps(finding.get("detail", {}), indent=2))}</pre></details></td></tr>')
    checks = []
    for cid, aggregate in details.get("checks", {}).items():
        for check in aggregate.get("by_scope", [aggregate]):
            notes = "; ".join(check.get("errors", []) + check.get("stop_reasons", [])) or check.get("reason", "")
            checks.append('<tr>' + "".join(f'<td>{esc(value)}</td>' for value in (cid, check.get("profile"),
                check.get("account_id"), check.get("agency_urn"), check.get("region"), check.get("project_id"), check["status"], check["count"], notes)) + '</tr>')
    coverage = "Complete for selected checks" if details.get("complete") else "INCOMPLETE — inspect failed checks and uninspected resources"
    profile_errors = [f'{name}: {error}' for name, record in details.get("profiles", {}).items() for error in record.get("errors", [])]
    report = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dredge — Huawei Security Review</title><style>
body{{font:14px/1.5 system-ui,sans-serif;margin:24px;color:#172033;background:#fff}}h1{{margin-bottom:4px}}
table{{border-collapse:collapse;width:100%;margin:16px 0}}th,td{{padding:8px;border:1px solid #ddd;text-align:left;vertical-align:top}}
th{{background:#edf2f7}}p{{margin:6px 0}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}select{{margin:0 16px 0 6px;padding:4px}}
.coverage{{padding:12px;background:{'#e3f3e8' if details.get('complete') else '#fff0d7'};font-weight:bold}}
</style></head><body><h1>Dredge — Huawei Security Review</h1>
<p>{esc(details.get('meta', {}).get('generated_at'))}</p><p class="coverage" role="status">{esc(coverage)}</p>
<p>{esc(' · '.join(f'{s}: {details.get("summary", {}).get(s, 0)}' for s in SEVERITIES))}</p>
<p>Findings identify conditions to assess. Zero findings do not establish complete coverage.</p>
<label>Severity<select id="severity">{options(SEVERITIES)}</select></label>
<label>Service<select id="service">{options(details.get('meta', {}).get('services', []))}</select></label>
<label>Profile<select id="profile">{options(details.get('profiles', {}))}</select></label>
<table id="findings"><thead><tr><th>Severity</th><th>Service</th><th>Check</th><th>Resource</th><th>Profile</th><th>Account</th><th>Agency</th><th>Region</th><th>Project</th><th>Finding</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan="10">No findings collected; inspect coverage below.</td></tr>'}</tbody></table>
<h2>Checks and coverage</h2><table><thead><tr><th>Check</th><th>Profile</th><th>Account</th><th>Agency</th><th>Region</th><th>Project</th><th>Status</th><th>Findings</th><th>Notes</th></tr></thead><tbody>{''.join(checks)}</tbody></table>
<h2>Errors</h2><pre>{esc(chr(10).join(result.errors + profile_errors))}</pre>
<details><summary>Uninspected resources ({len(details.get('uninspected', []))})</summary><pre>{esc(json.dumps(details.get('uninspected', []), indent=2))}</pre></details>
<details><summary>Assessment scope</summary><pre>{esc(json.dumps(details.get('meta', {}), indent=2))}</pre></details>
<script>const keys=['severity','service','profile'];function filter(){{document.querySelectorAll('#findings tbody tr').forEach(row=>{{row.hidden=keys.some(key=>{{const value=document.getElementById(key).value;return value&&row.dataset[key]!==value;}});}});}}
keys.forEach(key=>document.getElementById(key).addEventListener('change',filter));</script></body></html>'''
    Path(path).write_text(report, encoding="utf-8")
