import fs from "fs";

const events = JSON.parse(fs.readFileSync("events.json", "utf8"));
const state = JSON.parse(fs.readFileSync("state.json", "utf8"));
const stats = JSON.parse(fs.readFileSync("event-stats.json", "utf8"));
const mttd = JSON.parse(fs.readFileSync("mttd.json", "utf8"));
const policy = JSON.parse(fs.readFileSync("policy.json", "utf8"));

const html = `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8" />
<title>NCAOS Phase 05 Offline Evidence Dashboard</title>
<style>
body { background:#020812; color:#7efcff; font-family:Consolas, monospace; padding:20px; }
h1 { color:#35d3ff; letter-spacing:2px; }
.panel { border:1px solid #00c3ff66; background:#00142888; padding:14px; margin:12px 0; }
.badge { display:inline-block; border:1px solid #00c3ff66; padding:5px 9px; margin:4px; }
.high { color:#ff4d6d; font-weight:bold; }
.low { color:#00ff88; font-weight:bold; }
.med { color:#ffd166; font-weight:bold; }
.BLOCK { color:#ff4d6d; font-weight:bold; }
.DOWNGRADE { color:#ffd166; font-weight:bold; }
.PASS { color:#00ff88; font-weight:bold; }
table { width:100%; border-collapse:collapse; margin-top:10px; }
th, td { border-bottom:1px solid #00c3ff33; padding:8px; font-size:13px; text-align:left; }
</style>
</head>
<body>

<h1>NCAOS // Phase 05 Offline Evidence Dashboard</h1>

<div class="panel">
  <h2>Runtime Summary</h2>
  <span class="badge">Partner: ${policy.partnerId ?? "GLOBAL_ENT_2026"}</span>
  <span class="badge">Policy: ${policy.profileId ?? "STRICT-PROD"}</span>
  <span class="badge">Total Events: ${stats.total ?? events.records?.length ?? 0}</span>
  <span class="badge">SLA Healthy: ${mttd.slaHealthy}</span>
</div>

<div class="panel">
  <h2>System State</h2>
  <span class="badge">Mode: ${state.operationalMode ?? "—"}</span>
  <span class="badge">Integrity: ${state.integrity?.score ?? "—"}/100</span>
  <span class="badge">Authority: ${state.authority?.score ?? "—"}/100</span>
  <span class="badge">Continuity: ${state.continuityScore ?? "—"}/100</span>
</div>

<div class="panel">
  <h2>Event Log</h2>
  <table>
    <thead>
      <tr>
        <th>Request ID</th>
        <th>Layer</th>
        <th>Severity</th>
        <th>Action</th>
        <th>Evidence Handle</th>
        <th>Detected At</th>
      </tr>
    </thead>
    <tbody>
      ${(events.records ?? []).map(r => `
        <tr>
          <td>${r.event?.requestId ?? ""}</td>
          <td>${r.event?.layer ?? ""}</td>
          <td class="${r.event?.severity ?? ""}">${(r.event?.severity ?? "").toUpperCase()}</td>
          <td class="${r.verdict?.action ?? ""}">${r.verdict?.action ?? ""}</td>
          <td>${r.evidenceHandle ?? ""}</td>
          <td>${r.event?.detectedAt ?? ""}</td>
        </tr>
      `).join("")}
    </tbody>
  </table>
</div>

<div class="panel">
  <h2>MTTD / SLA</h2>
  <table>
    <thead>
      <tr><th>Layer</th><th>p50</th><th>p95</th><th>SLA ms</th><th>Breach Rate</th></tr>
    </thead>
    <tbody>
      ${(mttd.layers ?? []).map(x => `
        <tr>
          <td>${x.layer}</td>
          <td>${x.p50}</td>
          <td>${x.p95}</td>
          <td>${x.slaMs}</td>
          <td>${x.slaBreachRate}</td>
        </tr>
      `).join("")}
    </tbody>
  </table>
</div>

</body>
</html>
`;

fs.writeFileSync("phase05_offline_dashboard.html", html);
console.log("Created phase05_offline_dashboard.html");