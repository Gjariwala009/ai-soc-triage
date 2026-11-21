from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import sys
from typing import Optional

from ai_triage import AITriageHelper, load_dotenv_file
from privacy_scrubber import EnterpriseLogScrubber
from threat_intel import ThreatIntelChecker

load_dotenv_file()
INTEL_CHECKER = ThreatIntelChecker()


def run_pipeline(
    raw_log: str,
    gemini_key: Optional[str] = None,
    abuseipdb_key: Optional[str] = None,
) -> dict:
    scrubber = EnterpriseLogScrubber()
    scrub_result = scrubber.sanitize_log(raw_log)

    ip_reports = {}
    for ip in scrub_result["public_ips"]:
        ip_reports[ip] = INTEL_CHECKER.check_ip(ip, api_key=abuseipdb_key)

    triage_helper = AITriageHelper()
    injection_flag = bool(scrub_result["prompt_injection_attempt"])
    prompt_sent = triage_helper.build_prompt(
        str(scrub_result["sanitized_log"]),
        ip_reports,
        injection_flag,
    )
    triage_report = triage_helper.analyze_alert(scrub_result, ip_reports, api_key=gemini_key)

    local_summary = ""
    local_action = ""
    if "error" not in triage_report:
        local_summary = scrubber.detokenize(triage_report["summary"])
        local_action = scrubber.detokenize(triage_report["recommended_action"])

    return {
        "scrub_result": scrub_result,
        "ip_reports": ip_reports,
        "prompt_sent": prompt_sent,
        "triage_report": triage_report,
        "local_detokenized_summary": local_summary,
        "local_detokenized_action": local_action,
    }


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AegisTriage — Privacy-Preserving Log Sanitization &amp; Threat Intelligence Console</title>
  <style>
    :root {
      --bg: #0d1117;
      --surface: #161b22;
      --surface-elevated: #0d1117;
      --border: #21262d;
      --border-strong: #30363d;
      --text: #c9d1d9;
      --heading: #f0f6fc;
      --muted: #8b949e;
      --accent: #58a6ff;
      --high: #f85149;
      --med: #d29922;
      --low: #3fb950;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background-color: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      font-size: 13.5px;
      line-height: 1.5;
    }
    .wrap { max-width: 1220px; margin: 0 auto; padding: 24px 20px 56px; }
    .topbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 14px;
      padding-bottom: 16px;
      margin-bottom: 18px;
      border-bottom: 1px solid var(--border);
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .brand-icon {
      width: 36px;
      height: 36px;
      border-radius: 6px;
      background: var(--surface);
      border: 1px solid var(--border-strong);
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }
    .brand h1 {
      margin: 0;
      font-size: 18px;
      font-weight: 600;
      letter-spacing: -0.01em;
      color: var(--heading);
    }
    .brand-sub {
      margin: 2px 0 0;
      font-size: 12.5px;
      color: var(--muted);
    }
    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      padding: 4px 10px;
      border-radius: 6px;
      background: var(--surface);
      border: 1px solid var(--border-strong);
      color: var(--text);
      font-size: 12px;
      font-weight: 500;
    }
    .pulse-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--low);
    }
    .trace-bar {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 10px;
      margin-bottom: 18px;
    }
    @media (max-width: 860px) {
      .trace-bar { grid-template-columns: 1fr 1fr; }
    }
    .trace-step {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 10px 12px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      transition: border-color 0.15s ease;
    }
    .trace-left {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 12px;
      font-weight: 500;
      color: var(--muted);
    }
    .step-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: #484f58;
      flex-shrink: 0;
    }
    .trace-step.active {
      border-color: var(--accent);
    }
    .trace-step.active .trace-left { color: var(--heading); }
    .trace-step.active .step-dot {
      background: var(--accent);
    }
    .trace-step.done {
      border-color: var(--border-strong);
    }
    .trace-step.done .trace-left { color: var(--text); }
    .trace-step.done .step-dot { background: var(--low); }
    .trace-step.err {
      border-color: var(--high);
    }
    .trace-step.err .step-dot { background: var(--high); }
    .trace-status {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 11px;
      font-weight: 600;
      color: var(--muted);
    }
    .trace-step.active .trace-status { color: var(--accent); }
    .trace-step.done .trace-status { color: var(--low); }
    .trace-step.err .trace-status { color: var(--high); }
    .workbench {
      display: grid;
      grid-template-columns: 1fr 1.15fr;
      gap: 16px;
      align-items: start;
    }
    @media (max-width: 880px) {
      .workbench { grid-template-columns: 1fr; }
    }
    .col { display: flex; flex-direction: column; gap: 16px; }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 16px;
    }
    .card-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 10px;
      margin-bottom: 14px;
      padding-bottom: 10px;
      border-bottom: 1px solid var(--border);
    }
    .card-title {
      font-size: 13px;
      font-weight: 600;
      color: var(--heading);
    }
    .controls {
      display: flex;
      gap: 10px;
      margin-bottom: 12px;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
    }
    .file-label {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      background: #21262d;
      color: var(--text);
      border: 1px solid var(--border-strong);
      border-radius: 6px;
      padding: 7px 12px;
      font-size: 12.5px;
      font-weight: 500;
      cursor: pointer;
    }
    .file-label:hover {
      background: #30363d;
      border-color: #8b949e;
    }
    #fileInput { display: none; }
    .btn-primary {
      background: #238636;
      color: #ffffff;
      border: 1px solid rgba(240, 246, 252, 0.1);
      border-radius: 6px;
      padding: 7px 14px;
      font-size: 12.5px;
      font-weight: 600;
      cursor: pointer;
    }
    .btn-primary:hover { background: #2ea043; }
    .btn-primary:disabled { opacity: 0.55; cursor: not-allowed; }
    textarea {
      width: 100%;
      min-height: 144px;
      background: var(--surface-elevated);
      color: var(--heading);
      border: 1px solid var(--border-strong);
      border-radius: 6px;
      padding: 10px 12px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 12px;
      line-height: 1.5;
      resize: vertical;
      outline: none;
    }
    textarea:focus { border-color: var(--accent); }
    .mono {
      background: var(--surface-elevated);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 10px 12px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 12px;
      white-space: pre-wrap;
      word-break: break-word;
      color: var(--text);
    }
    .field-label {
      font-size: 11px;
      font-weight: 600;
      color: var(--muted);
      margin: 12px 0 5px;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }
    .field-label:first-child { margin-top: 0; }
    .meta-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      margin-bottom: 10px;
    }
    @media (max-width: 560px) {
      .meta-row { grid-template-columns: 1fr; }
    }
    .chip {
      display: inline-flex;
      align-items: center;
      padding: 2px 8px;
      border-radius: 4px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 11px;
      font-weight: 600;
      border: 1px solid var(--border-strong);
      background: var(--surface-elevated);
      color: var(--muted);
    }
    .chip-high { color: var(--high); border-color: rgba(248, 81, 73, 0.4); background: rgba(248, 81, 73, 0.1); }
    .chip-med { color: var(--med); border-color: rgba(210, 153, 34, 0.4); background: rgba(210, 153, 34, 0.1); }
    .chip-low { color: var(--low); border-color: rgba(63, 185, 80, 0.4); background: rgba(63, 185, 80, 0.1); }
    .chip-accent { color: var(--accent); border-color: rgba(88, 166, 255, 0.4); background: rgba(88, 166, 255, 0.1); }
    .conf-track {
      width: 100%;
      height: 6px;
      background: var(--surface-elevated);
      border: 1px solid var(--border-strong);
      border-radius: 3px;
      overflow: hidden;
      margin-top: 8px;
    }
    .conf-fill {
      height: 100%;
      background: var(--accent);
      width: 0%;
      transition: width 0.3s ease;
    }
    .step-cards {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .reason-card {
      display: flex;
      align-items: flex-start;
      gap: 10px;
      background: var(--surface-elevated);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 8px 10px;
      font-size: 12.5px;
      color: var(--text);
    }
    .reason-num {
      width: 18px;
      height: 18px;
      border-radius: 4px;
      background: var(--surface);
      border: 1px solid var(--border-strong);
      color: var(--muted);
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 11px;
      font-weight: 600;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      margin-top: 1px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 12px;
      background: var(--surface-elevated);
      border: 1px solid var(--border);
      border-radius: 6px;
      overflow: hidden;
    }
    th, td {
      text-align: left;
      padding: 8px 10px;
      border-bottom: 1px solid var(--border);
    }
    th {
      color: var(--muted);
      font-weight: 600;
      font-size: 11px;
      text-transform: uppercase;
      background: var(--surface);
    }
    tr:last-child td { border-bottom: none; }
    .hidden { display: none; }
    .err {
      color: var(--high);
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 12px;
      margin-top: 10px;
    }
  </style>
</head>
<body>
  <div class="wrap">
    <header class="topbar">
      <div class="brand">
        <div class="brand-icon" aria-hidden="true">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#8b949e" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="m9 12 2 2 4-4"/>
          </svg>
        </div>
        <div>
          <h1>Aegis Triage</h1>
          <p class="brand-sub">Privacy-Preserving Log Sanitization &amp; Threat Intelligence Console</p>
        </div>
      </div>
      <div class="status-pill">
        <span class="pulse-dot"></span>
        <span>Engine Ready</span>
      </div>
    </header>

    <div class="trace-bar">
      <div id="step1Trace" class="trace-step">
        <div class="trace-left"><span class="step-dot"></span><span>01 PII/PHI Tokenization</span></div>
        <span class="trace-status">READY</span>
      </div>
      <div id="step2Trace" class="trace-step">
        <div class="trace-left"><span class="step-dot"></span><span>02 Threat Intel Lookup</span></div>
        <span class="trace-status">READY</span>
      </div>
      <div id="step3Trace" class="trace-step">
        <div class="trace-left"><span class="step-dot"></span><span>03 AI Threat Analysis</span></div>
        <span class="trace-status">READY</span>
      </div>
      <div id="step4Trace" class="trace-step">
        <div class="trace-left"><span class="step-dot"></span><span>04 Local Re-hydration</span></div>
        <span class="trace-status">READY</span>
      </div>
    </div>

    <div class="workbench">
      <div class="col">
        <div class="card">
          <div class="card-head">
            <span class="card-title">Log Telemetry Input</span>
            <span id="fileNameTag" class="chip hidden"></span>
          </div>
          <div class="controls">
            <label for="fileInput" class="file-label">Upload .log / .txt File</label>
            <input id="fileInput" type="file" accept=".log,.txt,.json,.csv" onchange="handleFileUpload(event)" />
            <button id="runBtn" class="btn-primary" onclick="analyzeLog()">Run Triage Analysis</button>
          </div>
          <textarea id="logInput" placeholder="Paste any syslog, Windows Event / Sysmon entry, or healthcare audit log line here..."></textarea>
          <div id="errorBox" class="err hidden"></div>
        </div>

        <div id="scrubBox" class="card hidden">
          <div class="card-head">
            <span class="card-title">Sanitized Log &amp; Zero-PII Prompt</span>
            <span id="scrubTags" class="chip"></span>
          </div>
          <div class="field-label">Sanitized Telemetry</div>
          <div id="scrubbedLog" class="mono"></div>
          <div class="field-label">Exact Prompt Dispatched to AI (Zero-PII Proof)</div>
          <div id="promptSentBox" class="mono"></div>
        </div>
      </div>

      <div id="rightCol" class="col hidden">
        <div class="card">
          <div class="card-head">
            <span class="card-title">Threat Intelligence Enrichment</span>
            <span id="intelMode" class="chip"></span>
          </div>
          <div id="intelContent"></div>
        </div>

        <div class="card">
          <div class="card-head">
            <span class="card-title">AI Threat Assessment (<span id="modelName">gemini-3.8-flash</span>)</span>
            <span id="triageTags" class="chip"></span>
          </div>

          <div id="triageErrorBox" class="mono chip-high hidden"></div>

          <div id="triageSuccessBody">
            <div class="meta-row">
              <div>
                <div class="field-label">MITRE ATT&amp;CK Tactic</div>
                <div id="mitreTactic" class="mono"></div>
              </div>
              <div>
                <div class="field-label">Assessment Confidence: <span id="confVal" style="color:var(--accent)">0%</span></div>
                <div class="conf-track"><div id="confFill" class="conf-fill"></div></div>
              </div>
            </div>

            <div class="field-label">Attack Classification</div>
            <div id="attackType" class="mono"></div>

            <div class="field-label">Evidence &amp; Correlation Steps</div>
            <div id="reasoningSteps" class="step-cards"></div>

            <div class="field-label">Summary (Tokenized)</div>
            <div id="aiSummary" class="mono"></div>

            <div class="field-label">Recommended Containment</div>
            <div id="aiAction" class="mono"></div>
          </div>
        </div>

        <div id="restoredBox" class="card">
          <div class="card-head">
            <span class="card-title">Local Analyst View</span>
            <span class="chip chip-accent">Re-hydrated Locally</span>
          </div>
          <div class="field-label">Analyst Incident Summary</div>
          <div id="localSummary" class="mono"></div>
          <div class="field-label">Actionable Containment Checklist</div>
          <div id="localAction" class="mono"></div>
        </div>
      </div>
    </div>
  </div>

  <script>
    function handleFileUpload(event) {
      const file = event.target.files[0];
      if (!file) return;
      const tag = document.getElementById("fileNameTag");
      tag.textContent = file.name;
      tag.classList.remove("hidden");
      const reader = new FileReader();
      reader.onload = e => {
        document.getElementById("logInput").value = String(e.target.result || "").slice(0, 12000);
      };
      reader.readAsText(file);
    }

    function sevClass(sev) {
      if (sev === "CRITICAL" || sev === "HIGH") return "chip chip-high";
      if (sev === "MEDIUM") return "chip chip-med";
      return "chip chip-low";
    }

    function setTrace(id, state, label) {
      const el = document.getElementById(id);
      el.className = "trace-step" + (state ? " " + state : "");
      el.querySelector(".trace-status").textContent = label;
    }

    function renderReasoningSteps(container, steps) {
      container.innerHTML = "";
      (steps || []).forEach((stepText, idx) => {
        const card = document.createElement("div");
        card.className = "reason-card";

        const num = document.createElement("span");
        num.className = "reason-num";
        num.textContent = String(idx + 1);

        const body = document.createElement("span");
        body.textContent = String(stepText).replace(/^\d+\.\s*/, "");

        card.appendChild(num);
        card.appendChild(body);
        container.appendChild(card);
      });
    }

    async function analyzeLog() {
      const errorBox = document.getElementById("errorBox");
      const runBtn = document.getElementById("runBtn");
      errorBox.classList.add("hidden");

      const rawLog = document.getElementById("logInput").value.trim();
      if (!rawLog) {
        errorBox.textContent = "Please paste a security log or upload a .log / .txt file first.";
        errorBox.classList.remove("hidden");
        return;
      }

      runBtn.disabled = true;
      setTrace("step1Trace", "active", "SCRUBBING");
      setTrace("step2Trace", "active", "QUERYING");
      setTrace("step3Trace", "active", "ANALYZING");
      setTrace("step4Trace", "", "WAIT");

      let resp, data;
      try {
        resp = await fetch("/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ raw_log: rawLog })
        });
        data = await resp.json();
      } catch (err) {
        runBtn.disabled = false;
        setTrace("step3Trace", "err", "ERROR");
        errorBox.textContent = "Network error: " + err;
        errorBox.classList.remove("hidden");
        return;
      }

      if (!resp.ok) {
        runBtn.disabled = false;
        setTrace("step3Trace", "err", "ERROR");
        errorBox.textContent = data.error || "Request failed";
        errorBox.classList.remove("hidden");
        return;
      }

      setTrace("step1Trace", "done", "DONE");
      setTrace("step2Trace", "done", "DONE");

      const scrubTags = document.getElementById("scrubTags");
      const injFlag = data.scrub_result.prompt_injection_attempt;
      scrubTags.textContent = "Tokens: " + data.scrub_result.tokens_mapped + (injFlag ? " | Injection Blocked" : " | Clean");
      scrubTags.className = injFlag ? "chip chip-high" : "chip chip-low";
      document.getElementById("scrubbedLog").textContent = data.scrub_result.sanitized_log;
      document.getElementById("promptSentBox").textContent = data.prompt_sent;
      document.getElementById("scrubBox").classList.remove("hidden");

      const intelContent = document.getElementById("intelContent");
      intelContent.innerHTML = "";
      const ips = Object.entries(data.ip_reports);
      if (ips.length === 0) {
        const empty = document.createElement("div");
        empty.className = "mono";
        empty.textContent = "No public IPv4 addresses detected (private RFC 1918 / internal scope only).";
        intelContent.appendChild(empty);
        document.getElementById("intelMode").textContent = "Internal Only";
        document.getElementById("intelMode").className = "chip";
      } else {
        const table = document.createElement("table");
        const thead = document.createElement("thead");
        thead.innerHTML = "<tr><th>IP Address</th><th>Risk Score</th><th>Network / Country</th><th>Classification</th><th>Origin</th></tr>";
        table.appendChild(thead);
        const tbody = document.createElement("tbody");

        let anyCached = false;
        ips.forEach(([ip, info]) => {
          if (info.from_cache) anyCached = true;
          const tr = document.createElement("tr");
          const scoreCls = info.abuse_score >= 80 ? "chip chip-high" : (info.abuse_score >= 30 ? "chip chip-med" : "chip chip-low");
          const flags = [];
          if (info.proxy) flags.push("PROXY/TOR");
          if (info.hosting) flags.push("HOSTING");

          const tdIp = document.createElement("td");
          tdIp.textContent = ip;

          const tdScore = document.createElement("td");
          const scSpan = document.createElement("span");
          scSpan.className = scoreCls;
          scSpan.textContent = info.abuse_score + "/100";
          tdScore.appendChild(scSpan);

          const tdNet = document.createElement("td");
          tdNet.textContent = (info.country || "?") + " — " + (info.isp || "?");

          const tdClass = document.createElement("td");
          tdClass.textContent = flags.length ? flags.join(", ") : "STANDARD ISP";

          const tdSrc = document.createElement("td");
          tdSrc.textContent = (info.from_cache ? "CACHED: " : "LIVE: ") + info.source;

          [tdIp, tdScore, tdNet, tdClass, tdSrc].forEach(td => tr.appendChild(td));
          tbody.appendChild(tr);
        });
        table.appendChild(tbody);
        intelContent.appendChild(table);
        document.getElementById("intelMode").textContent = anyCached ? "Cache Hit" : "Live Feed";
        document.getElementById("intelMode").className = anyCached ? "chip chip-low" : "chip chip-accent";
      }

      const triage = data.triage_report;
      const triageErrBox = document.getElementById("triageErrorBox");
      const triageBody = document.getElementById("triageSuccessBody");
      const restoredBox = document.getElementById("restoredBox");
      const triageTags = document.getElementById("triageTags");

      if (triage.error) {
        setTrace("step3Trace", "err", "FAILED");
        setTrace("step4Trace", "", "SKIPPED");
        triageTags.textContent = "ERROR";
        triageTags.className = "chip chip-high";
        triageErrBox.textContent = triage.error;
        triageErrBox.classList.remove("hidden");
        triageBody.classList.add("hidden");
        restoredBox.classList.add("hidden");
      } else {
        setTrace("step3Trace", "done", "DONE");
        setTrace("step4Trace", "done", "DONE");
        triageErrBox.classList.add("hidden");
        triageBody.classList.remove("hidden");
        restoredBox.classList.remove("hidden");

        document.getElementById("modelName").textContent = triage.model || "gemini-3.8-flash";
        triageTags.textContent = triage.severity;
        triageTags.className = sevClass(triage.severity);

        const conf = Math.max(0, Math.min(100, Number(triage.confidence || 0)));
        document.getElementById("confVal").textContent = conf + "%";
        document.getElementById("confFill").style.width = conf + "%";
        document.getElementById("mitreTactic").textContent = triage.mitre_tactic || "Unclassified";
        document.getElementById("attackType").textContent = triage.attack_type;

        renderReasoningSteps(document.getElementById("reasoningSteps"), triage.reasoning_steps);

        document.getElementById("aiSummary").textContent = triage.summary;
        document.getElementById("aiAction").textContent = triage.recommended_action;

        document.getElementById("localSummary").textContent = data.local_detokenized_summary;
        document.getElementById("localAction").textContent = data.local_detokenized_action;
      }

      document.getElementById("rightCol").classList.remove("hidden");
      runBtn.disabled = false;
    }
  </script>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    def _send_json(self, status_code: int, payload: dict) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        route = self.path.split("?", 1)[0]
        if route == "/api/health":
            self._send_json(
                200,
                {
                    "status": "ok",
                    "gemini_configured": bool(os.getenv("GEMINI_API_KEY")),
                    "abuseipdb_configured": bool(os.getenv("ABUSEIPDB_API_KEY")),
                },
            )
            return

        if route not in ("/", "/index.html", "/api/index"):
            self._send_json(404, {"error": "Not found"})
            return

        html = DASHBOARD_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def do_POST(self) -> None:
        route = self.path.split("?", 1)[0]
        if route not in ("/analyze", "/api/analyze"):
            self._send_json(404, {"error": "Not found"})
            return

        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            self._send_json(400, {"error": "Invalid JSON request body."})
            return

        raw_log = str(body.get("raw_log", "")).strip()
        if not raw_log:
            self._send_json(400, {"error": "raw_log cannot be empty."})
            return

        self._send_json(200, run_pipeline(raw_log))

    def log_message(self, format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    if "--check" in sys.argv:
        print("AegisTriage OK (gemini_env_set=%s)" % bool(os.getenv("GEMINI_API_KEY")))
    else:
        server = ThreadingHTTPServer(("127.0.0.1", 8080), DashboardHandler)
        print("AegisTriage running at http://127.0.0.1:8080 (Ctrl+C to stop)")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down.")
            server.server_close()
