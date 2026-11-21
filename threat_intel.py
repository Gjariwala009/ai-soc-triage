import json
import os
from typing import Optional
import urllib.parse
import urllib.request


class ThreatIntelChecker:
    """Live IP reputation checker using ip-api.com and optional AbuseIPDB lookups."""

    IP_API_URL = "http://ip-api.com/json"
    ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
        # cache per (ip, has_abuseipdb_key) to avoid burning API quotas on repeated alerts
        self.checked_ips: dict[tuple[str, bool], dict] = {}

    def _query_ip_api(self, ip: str) -> dict:
        fields = "status,message,country,isp,org,as,proxy,hosting"
        url = f"{self.IP_API_URL}/{urllib.parse.quote(ip)}?fields={fields}"
        request = urllib.request.Request(url, headers={"User-Agent": "ehr-log-triage/1.0"})

        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                data = json.loads(response.read().decode("utf-8"))
        except Exception as error:
            return {
                "abuse_score": 0,
                "country": "Unknown",
                "isp": "Lookup failed",
                "org": "Unknown",
                "asn": "Unknown",
                "proxy": False,
                "hosting": False,
                "total_reports": 0,
                "source": f"ip-api (error: {type(error).__name__})",
            }

        if data.get("status") != "success":
            return {
                "abuse_score": 0,
                "country": "Unknown",
                "isp": data.get("message", "Lookup failed"),
                "org": "Unknown",
                "asn": "Unknown",
                "proxy": False,
                "hosting": False,
                "total_reports": 0,
                "source": "ip-api (unavailable)",
            }

        is_proxy = bool(data.get("proxy", False))
        is_hosting = bool(data.get("hosting", False))
        if is_proxy:
            derived_score = 85
        elif is_hosting:
            derived_score = 45
        else:
            derived_score = 5

        return {
            "abuse_score": derived_score,
            "country": data.get("country", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "org": data.get("org", "Unknown"),
            "asn": data.get("as", "Unknown"),
            "proxy": is_proxy,
            "hosting": is_hosting,
            "total_reports": 0,
            "source": "ip-api (live)",
        }

    def _query_abuseipdb(self, ip: str, api_key: str) -> Optional[dict]:
        params = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": "90"})
        request = urllib.request.Request(
            f"{self.ABUSEIPDB_URL}?{params}",
            headers={"Key": api_key, "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))
                return payload.get("data", {})
        except Exception:
            return None

    def check_ip(self, ip: str, api_key: Optional[str] = None) -> dict:
        effective_key = (api_key or self.api_key or "").strip()
        cache_key = (ip, bool(effective_key))

        if cache_key in self.checked_ips:
            cached = self.checked_ips[cache_key].copy()
            cached["from_cache"] = True
            return cached

        result = self._query_ip_api(ip)
        if effective_key:
            abuse_data = self._query_abuseipdb(ip, effective_key)
            if abuse_data is not None:
                result["abuse_score"] = abuse_data.get("abuseConfidenceScore", result["abuse_score"])
                result["isp"] = abuse_data.get("isp") or result["isp"]
                result["total_reports"] = abuse_data.get("totalReports", 0)
                result["source"] = "abuseipdb + ip-api (live)"
            else:
                result["source"] = f"{result['source']} [abuseipdb failed]"

        self.checked_ips[cache_key] = result.copy()
        output = result.copy()
        output["from_cache"] = False
        return output


if __name__ == "__main__":
    checker = ThreatIntelChecker()
    print(json.dumps(checker.check_ip("185.220.101.42"), indent=2))
    print(json.dumps(checker.check_ip("185.220.101.42"), indent=2))
