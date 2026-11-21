import ipaddress
import re


class EnterpriseLogScrubber:
    """Masks emails, 10-digit HCNs, and private RFC 1918 IPs with reversible tokens."""

    EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
    HCN_REGEX = re.compile(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b")
    IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    INJECTION_REGEX = re.compile(
        r"(ignore\s+previous\s+instructions|system\s+override|disregard\s+all|you\s+are\s+now)",
        re.IGNORECASE,
    )

    def __init__(self) -> None:
        self.token_vault: dict[str, str] = {}
        self.reverse_vault: dict[str, str] = {}
        self.counters: dict[str, int] = {"EMAIL": 0, "HCN": 0, "INTERNAL_IP": 0}

    def _get_token(self, value: str, category: str) -> str:
        if value in self.reverse_vault:
            return self.reverse_vault[value]

        self.counters[category] += 1
        token = f"[{category}_{self.counters[category]}]"
        self.token_vault[token] = value
        self.reverse_vault[value] = token
        return token

    def _handle_ip(self, match: re.Match[str], public_ips: list[str]) -> str:
        ip_str = match.group(0)
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return ip_str

        if ip_obj.is_private or ip_obj.is_loopback:
            return self._get_token(ip_str, "INTERNAL_IP")

        # keep public IPs intact so we can check AbuseIPDB
        if ip_str not in public_ips:
            public_ips.append(ip_str)
        return ip_str

    def sanitize_log(self, raw_log: str) -> dict[str, object]:
        injection_detected = bool(self.INJECTION_REGEX.search(raw_log))
        cleaned = self.INJECTION_REGEX.sub("[PROMPT_INJECTION_BLOCKED]", raw_log)

        cleaned = self.EMAIL_REGEX.sub(
            lambda m: self._get_token(m.group(0), "EMAIL"),
            cleaned,
        )
        cleaned = self.HCN_REGEX.sub(
            lambda m: self._get_token(m.group(0), "HCN"),
            cleaned,
        )

        public_ips: list[str] = []
        cleaned = self.IPV4_REGEX.sub(
            lambda m: self._handle_ip(m, public_ips),
            cleaned,
        )

        return {
            "sanitized_log": cleaned,
            "public_ips": public_ips,
            "prompt_injection_attempt": injection_detected,
            "tokens_mapped": len(self.token_vault),
        }

    def detokenize(self, text: str) -> str:
        restored = text
        for token, original_value in self.token_vault.items():
            restored = restored.replace(token, original_value)
        return restored


if __name__ == "__main__":
    sample = (
        "2026-11-20T09:14:22Z sshd[4821]: Failed password for invalid user "
        "jsmith@nshealth.ca (HCN: 987-654-3210) from 185.220.101.42 port 54321 "
        "-> dest 10.24.8.15"
    )
    scrubber = EnterpriseLogScrubber()
    res = scrubber.sanitize_log(sample)
    print("sanitized:", res["sanitized_log"])
    print("public_ips:", res["public_ips"])
    print("restored:", scrubber.detokenize(str(res["sanitized_log"])))
