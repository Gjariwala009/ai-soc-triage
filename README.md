# AegisTriage

Privacy-Preserving Log Sanitization & Threat Intelligence Console built in Python. Scrubs sensitive identifiers out of syslog, Windows Sysmon, and healthcare audit logs before enriching public IPs and running live alert triage with Gemini 3.8 Flash.

## How it works

1. **PIPEDA Sanitization (`privacy_scrubber.py`):** Replaces emails, 10-digit Health Card Numbers (HCNs), and private RFC 1918 IPv4 addresses with session-scoped tokens (`[EMAIL_1]`, `[HCN_1]`, `[INTERNAL_IP_1]`) and strips common log-based prompt-injection patterns. Public IPv4 addresses stay intact for threat-intel lookups.
2. **Live IP Enrichment (`threat_intel.py`):** Queries `ip-api.com` in real time for Country, ISP, ASN, and Proxy/Tor/Hosting flags on any extracted public IPs—and optionally queries AbuseIPDB if `ABUSEIPDB_API_KEY` is configured—with in-memory caching to avoid duplicate API requests.
3. **Live AI Triage (`ai_triage.py`):** Sends only the scrubbed log and live IP intel JSON to `gemini-3.8-flash` with JSON output enforced (`severity`, `attack_type`, `mitre_tactic`, `confidence`, `reasoning_steps`, `summary`, `recommended_action`).
4. **Local Analyst Workbench (`dashboard.py` & `api/index.py`):** Dependency-free web UI (served locally or via Vercel Python serverless) that displays the exact Zero-PII prompt sent to Gemini alongside the locally detokenized analyst report.

## Run Locally

1. Set your Gemini API key (and optional AbuseIPDB key) via environment variables or a local `.env` file:
   ```bash
   export GEMINI_API_KEY="your_gemini_api_key"
   export ABUSEIPDB_API_KEY="your_abuseipdb_key"   # optional
   python3 dashboard.py
   ```
2. Open `http://127.0.0.1:8080`, paste any real log line or upload a `.log`/`.txt` file, and click **Run AI Assessment**. (If you don't set `GEMINI_API_KEY` on the server, you can also enter it directly in the browser config bar.)

## Deploy to GitHub & Vercel

1. Push the `ai-soc-triage` folder as a Git repository to GitHub:
   ```bash
   cd ai-soc-triage
   git init
   git add .
   git commit -m "Initial commit: ehr-log-triage"
   git branch -M main
   git remote add origin https://github.com/<your-username>/ehr-log-triage.git
   git push -u origin main
   ```
2. In **Vercel**, click **Add New Project** and import the `ehr-log-triage` repository.
3. Under **Environment Variables**, add:
   - `GEMINI_API_KEY` = your Google AI Studio Gemini key
   - `ABUSEIPDB_API_KEY` = your AbuseIPDB key *(optional)*
4. Click **Deploy**. Vercel routes all requests through `vercel.json` to `api/index.py` using Python's standard library.
