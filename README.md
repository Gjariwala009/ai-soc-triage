# AegisTriage — Privacy-Preserving Healthcare SOC Log Sanitization & Triage Console

SOC analysts frequently paste raw syslog, Windows Sysmon, or EHR audit logs into external LLMs during incident triage—inadvertently leaking patient Health Card Numbers (HCNs), clinician emails, and internal hospital subnet layouts under PIPEDA/PHIPA.

**AegisTriage** is a dependency-free Python SOC triage console that tokenizes sensitive PII/PHI and internal network topology on-premise before dispatching telemetry to an LLM, enriches only routable public IPs against live threat intelligence, quarantines log-based prompt injections, and re-hydrates the final analyst report locally within a single stateless request lifecycle.

---

## Architecture & 4-Stage Pipeline

```text
[Raw Security / EHR Audit Log]
       │
       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 01. Ephemeral Tokenization & Injection Quarantine (privacy_scrubber.py) │
│  • Masks emails -> [EMAIL_1]                                            │
│  • Masks contextual/Luhn 10-digit HCNs (+ Ontario version codes) ->     │
│    [HCN_1] (avoids bare epoch timestamp false positives)                │
│  • Masks RFC 1918, Loopback, Link-Local, CGNAT (100.64/10), IPv6 ULA -> │
│    [INTERNAL_IP_1]                                                      │
│  • Quarantines adversarial prompt-injection payloads locally            │
└──────┬──────────────────────────────────────────────────────────┬───────┘
       │ Sanitized Log + Public IPs Only                          │ Ephemeral In-Memory
       ▼                                                          │ Token Vault
┌────────────────────────────────────────────────────────┐        │ (Single Invocation)
│ 02. Public IP Threat Intel Enrichment (threat_intel.py)│        │
│  • Queries ip-api.com (Country, ASN, ISP, Proxy/Tor)   │        │
│  • Optional AbuseIPDB confidence score & total reports │        │
└──────┬─────────────────────────────────────────────────┘        │
       │ Sanitized Log + Public IP Intel JSON                     │
       ▼                                                          │
┌────────────────────────────────────────────────────────┐        │
│ 03. AI Triage + Deterministic Fallback (ai_triage.py)  │        │
│  • Calls gemini-3-flash-preview with strict JSON       │        │
│  • Validates MITRE ATT&CK tactic against canonical IDs │        │
│  • Automatic rule-based SOC fallback if LLM is offline │        │
└──────┬─────────────────────────────────────────────────┘        │
       │ Tokenized Triage Report ([EMAIL_1], [HCN_1], ...)        │
       ▼                                                          ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 04. Single-Invocation Re-hydration & Vault Wipe (dashboard.py)          │
│  • Restores tokens locally for the SOC analyst's containment checklist  │
│  • Explicitly clears the in-memory token vault before returning JSON    │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Sample Input & Output

### Raw Input Log
```text
Nov 20 09:14:22 nsha-ehr-gw01 sshd[4821]: Failed password for invalid user nurse.jane@hospital.ca (HCN: 9876543210) from 45.155.205.233 port 54321 ssh2 -> internal 10.0.0.15 / 192.168.1.10
```

### Stage 01: Sanitized Telemetry Sent to LLM
```text
Nov 20 09:14:22 nsha-ehr-gw01 sshd[4821]: Failed password for invalid user [EMAIL_1] (HCN: [HCN_1]) from 45.155.205.233 port 54321 ssh2 -> internal [INTERNAL_IP_1] / [INTERNAL_IP_2]
```

### Stage 03: Tokenized AI Assessment (`gemini-3-flash-preview`)
- **Severity**: `HIGH` | **MITRE Tactic**: `TA0006 - Credential Access`
- **Tokenized Summary**: `External host 45.155.205.233 attempted an SSH password failure against user [EMAIL_1] (associated with record [HCN_1]) across internal endpoints [INTERNAL_IP_1] and [INTERNAL_IP_2].`

### Stage 04: Re-hydrated Local Analyst View
- **Analyst Incident Summary**: `External host 45.155.205.233 attempted an SSH password failure against user nurse.jane@hospital.ca (associated with record 9876543210) across internal endpoints 10.0.0.15 and 192.168.1.10.`

---

## Run Locally

No third-party pip packages are required (built entirely on Python's standard library).

```bash
export GEMINI_API_KEY="your_gemini_api_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_key"   # optional
python3 dashboard.py
```

Open `http://127.0.0.1:8080`. Note: If `GEMINI_API_KEY` is omitted or unreachable, the console automatically degrades to its deterministic SOC rule-based triage engine so the pipeline never freezes.

### Run Unit Tests

```bash
python3 -m unittest discover -v
```

---

## CI/CD Pipeline (`dev` → `main` → Production)

This repository uses GitHub Actions ([`.github/workflows/ci-cd.yml`](.github/workflows/ci-cd.yml)) for continuous integration and automated promotion to production:

1. **Push to `dev`**: Every push to `dev` triggers the `test-and-verify` job, which compiles all Python modules, runs the `unittest` suite (`test_scrubber.py`), and executes an end-to-end 4-stage pipeline smoke test across all 3 healthcare SOC log scenarios (SSH Brute-Force + HCN, EHR Bulk Export + Ontario HCN/CGNAT, and Sysmon Prompt-Injection Quarantine).
2. **Automated Promotion to `main` (Production)**: Only if `test-and-verify` passes 100%, the `promote-to-main` job automatically merges the verified `dev` commit into `main` and pushes to `origin/main`, triggering Vercel's production deployment.

---

## Security Design & Honest Limitations

- **Ephemeral Deterministic Session Tokens**: Within a single request invocation, identical identifiers map to the same token (e.g., `[EMAIL_1]`) so the LLM can correlate multi-line events without seeing raw values. Because the bidirectional mapping exists in memory during request execution, it is an **ephemeral per-request pseudonymization store**, not cryptographic zero-knowledge proof. The vault is never logged to disk and is explicitly cleared (`token_vault.clear()`) before the HTTP response finishes.
- **Stateless Single-Invocation Re-hydration**: To avoid serverless cold-start state loss on Vercel, scrubbing, IP enrichment, LLM triage, and local detokenization all execute in a single atomic POST request (`/api/index`).
- **Heuristic Regex vs. Unstructured Free-Text PHI**: `privacy_scrubber.py` uses context-aware patterns, Luhn checksum validation, and Ontario 2-letter version code matching for HCNs, plus `ipaddress` network validation for RFC 1918, loopback, link-local, CGNAT (`100.64.0.0/10`), and IPv6 ULA. However, regex scrubbing cannot guarantee detection of arbitrary free-text clinical notes or unformatted patient names. **Do not use this demo deployment with live production PHI.**
- **Demo Guardrails**: Includes a sliding-window rate limiter (15 requests/minute per client IP) and a 12,000-character payload cap to protect AbuseIPDB and Gemini quotas.
