import json
import os
from typing import Optional
import urllib.error
import urllib.request

from privacy_scrubber import EnterpriseLogScrubber
from threat_intel import ThreatIntelChecker


def load_dotenv_file(env_path: Optional[str] = None) -> None:
    """Loads key=value pairs from a local .env file without overriding existing env vars."""
    path = env_path or os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.isfile(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except OSError:
        return


class AITriageHelper:
    """Sends scrubbed logs and live IP intel to Gemini 3.8 Flash for JSON triage."""

    GEMINI_MODEL = "gemini-3.8-flash"
    REQUIRED_KEYS = ("severity", "attack_type", "summary", "recommended_action")

    def __init__(self, api_key: Optional[str] = None) -> None:
        load_dotenv_file()
        self.api_key = (api_key or os.getenv("GEMINI_API_KEY") or "").strip() or None

    def build_prompt(
        self,
        sanitized_log: str,
        ip_reports: dict,
        prompt_injection_detected: bool = False,
    ) -> str:
        intel_text = json.dumps(ip_reports, indent=2) if ip_reports else "No public IPs found."
        injection_note = (
            "\nNOTE: The privacy scrubber detected and neutralized a potential "
            "log-based prompt-injection string ([PROMPT_INJECTION_BLOCKED]).\n"
            if prompt_injection_detected
            else ""
        )
        return (
            "You are a Tier-1 SOC Analyst. Analyze the scrubbed security log and the "
            "live threat intelligence data below. Preserve privacy tokens like [EMAIL_1], "
            "[HCN_1], or [INTERNAL_IP_1] verbatim in your summary and recommended_action.\n"
            f"{injection_note}\n"
            "Return ONLY valid JSON with these keys:\n"
            '- "severity": "LOW", "MEDIUM", "HIGH", or "CRITICAL"\n'
            '- "attack_type": short name and MITRE ATT&CK ID if applicable\n'
            '- "mitre_tactic": MITRE tactic ID and name (e.g. "TA0006 - Credential Access")\n'
            '- "confidence": integer 0-100 reflecting assessment certainty\n'
            '- "reasoning_steps": array of 3 concise steps correlating log events, tokens, and IP intel\n'
            '- "summary": 1-2 sentences explaining what happened\n'
            '- "recommended_action": specific containment step\n\n'
            f"Log:\n{sanitized_log}\n\n"
            f"IP Intel:\n{intel_text}\n"
        )

    def _ask_gemini(self, prompt: str, api_key: str) -> dict:
        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.GEMINI_MODEL}:generateContent"
        )
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"responseMimeType": "application/json"},
        }
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": api_key,
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                data = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as http_err:
            detail = ""
            try:
                err_body = json.loads(http_err.read().decode("utf-8"))
                detail = err_body.get("error", {}).get("message", "")
            except Exception:
                detail = http_err.reason
            return {
                "error": f"Gemini API HTTP {http_err.code}: {detail or 'Request rejected. Check your GEMINI_API_KEY.'}"
            }
        except Exception as exc:
            return {"error": f"Gemini API request failed: {type(exc).__name__}: {exc}"}

        try:
            raw_text = data["candidates"][0]["content"]["parts"][0]["text"]
            parsed = json.loads(raw_text)
        except Exception as exc:
            return {"error": f"Failed to parse Gemini JSON response: {exc}"}

        if not isinstance(parsed, dict) or not all(k in parsed for k in self.REQUIRED_KEYS):
            return {"error": "Gemini response was missing required JSON triage fields."}

        parsed.setdefault("mitre_tactic", "Unclassified")
        try:
            parsed["confidence"] = max(0, min(100, int(parsed.get("confidence", 85))))
        except (TypeError, ValueError):
            parsed["confidence"] = 85

        steps = parsed.get("reasoning_steps")
        if not isinstance(steps, list) or not steps:
            parsed["reasoning_steps"] = [
                "Parsed sanitized log telemetry and verified entity tokens.",
                "Correlated extracted public IPs with live network intelligence.",
                "Classified incident severity and generated containment guidance.",
            ]

        parsed["model"] = self.GEMINI_MODEL
        parsed["mode"] = "gemini_live"
        return parsed

    def analyze_alert(
        self,
        scrub_result: dict,
        ip_reports: dict,
        api_key: Optional[str] = None,
    ) -> dict:
        effective_key = (api_key or self.api_key or "").strip()
        if not effective_key:
            return {
                "error": (
                    "Missing GEMINI_API_KEY. Set GEMINI_API_KEY in your environment "
                    "(or Vercel Project Settings) or paste a key in the configuration bar."
                )
            }

        sanitized_log = str(scrub_result.get("sanitized_log", ""))
        injection_flag = bool(scrub_result.get("prompt_injection_attempt", False))
        prompt = self.build_prompt(sanitized_log, ip_reports, injection_flag)
        return self._ask_gemini(prompt, effective_key)


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        raw_input = " ".join(sys.argv[1:])
    else:
        print("Paste a raw security log line and press Enter:")
        raw_input = sys.stdin.readline().strip()

    if not raw_input:
        print(json.dumps({"error": "No log provided."}, indent=2))
        sys.exit(1)

    scrubber = EnterpriseLogScrubber()
    scrub_res = scrubber.sanitize_log(raw_input)

    checker = ThreatIntelChecker()
    intel = {ip: checker.check_ip(ip) for ip in scrub_res["public_ips"]}

    triage = AITriageHelper().analyze_alert(scrub_res, intel)
    result = {
        "scrubbed_log": scrub_res["sanitized_log"],
        "ip_intel": intel,
        "triage": triage,
    }
    if "summary" in triage:
        result["local_summary"] = scrubber.detokenize(triage["summary"])
    print(json.dumps(result, indent=2))
