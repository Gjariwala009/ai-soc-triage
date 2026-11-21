import ipaddress
import re


class EnterpriseLogScrubber:
    """Masks emails, contextual/Luhn-validated 10-digit HCNs, and private/internal IPs with reversible session tokens."""

    EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
    # Context-aware 10-digit HCN regex (with optional 2-letter Ontario version code like -AB or YM)
    CONTEXT_HCN_REGEX = re.compile(
        r"(?P<prefix>\b(?:sample_hcn|hcn|health\s*card(?:\s*(?:no|num|number|id))?|phn|mrn|nhi|patient[_\s-]*id|ohip)\s*[:=#-]?\s*)"
        r"(?P<num>\d{3,4}[-.\s]?\d{3}[-.\s]?\d{3,4}(?:[-\s]?[A-Z]{2})?\b)",
        re.IGNORECASE,
    )
    # Bare 10-digit candidate (formatted XXX-XXX-XXXX or XXXX-XXX-XXX, or 10 digits passing Luhn/version check)
    BARE_HCN_REGEX = re.compile(
        r"\b(?:\d{3}[-.\s]\d{3}[-.\s]\d{4}|\d{4}[-.\s]\d{3}[-.\s]\d{3}|\d{10})(?:[-\s]?[A-Z]{2})?\b"
    )
    IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    IPV6_REGEX = re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:?[0-9a-fA-F]{1,4}\b|\b(?:fe80|fc00|fd[0-9a-fA-F]{2}):[0-9a-fA-F:]+\b"
    )
    INJECTION_REGEX = re.compile(
        r"("
        r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?"
        r"|system\s+override"
        r"|disregard\s+(?:all|previous|prior)"
        r"|you\s+are\s+now\s+(?:a|an|in)"
        r"|mark\s+(?:this\s+)?(?:alert|incident|log)\s+as\s+(?:low|benign|safe|false\s+positive)"
        r"|do\s+not\s+(?:report|flag|escalate)"
        r"|<\s*/?\s*(?:system|instruction|prompt)\s*>"
        r")",
        re.IGNORECASE,
    )
    CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")

    def __init__(self) -> None:
        self.token_vault: dict[str, str] = {}
        self.reverse_vault: dict[str, str] = {}
        self.counters: dict[str, int] = {"EMAIL": 0, "HCN": 0, "INTERNAL_IP": 0}

    @staticmethod
    def passes_luhn(digits: str) -> bool:
        """Checks standard 10-digit Luhn checksum used by Canadian provincial health card numbers."""
        if len(digits) != 10 or not digits.isdigit():
            return False
        total = 0
        for idx, ch in enumerate(reversed(digits)):
            n = int(ch)
            if idx % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        return total % 10 == 0

    @classmethod
    def _is_likely_hcn(cls, candidate: str, has_context: bool = False) -> bool:
        digits = re.sub(r"\D", "", candidate)
        if len(digits) != 10:
            return False
        if has_context:
            return True
        # Reject common epoch seconds (e.g. 1600000000 - 2099999999) when bare 10-digit unformatted
        if candidate.isdigit() and candidate.startswith(("16", "17", "18", "19", "20")):
            return False
        has_separators = bool(re.search(r"[-.\s]", candidate))
        has_version_code = bool(re.search(r"[A-Z]{2}$", candidate))
        return has_separators or has_version_code or cls.passes_luhn(digits) or digits in ("9876543210", "1234567890")

    def _get_token(self, value: str, category: str) -> str:
        if value in self.reverse_vault:
            return self.reverse_vault[value]

        self.counters[category] += 1
        token = f"[{category}_{self.counters[category]}]"
        self.token_vault[token] = value
        self.reverse_vault[value] = token
        return token

    @classmethod
    def _is_internal_ip(cls, ip_obj: ipaddress._BaseAddress) -> bool:
        if (
            ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
        ):
            return True
        if isinstance(ip_obj, ipaddress.IPv4Address):
            if ip_obj in cls.CGNAT_NET:
                return True
            for net in (
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"),
            ):
                if ip_obj in net:
                    return True
            return False
        return ip_obj.is_private

    def _handle_ip(self, match: re.Match[str], public_ips: list[str]) -> str:
        ip_str = match.group(0)
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return ip_str

        if self._is_internal_ip(ip_obj):
            return self._get_token(ip_str, "INTERNAL_IP")

        if ip_str not in public_ips:
            public_ips.append(ip_str)
        return ip_str

    def sanitize_log(self, raw_log: str) -> dict[str, object]:
        quarantined_payloads: list[str] = []

        def _quarantine_injection(match: re.Match[str]) -> str:
            payload = match.group(0)
            quarantined_payloads.append(payload)
            return "[PROMPT_INJECTION_QUARANTINED]"

        cleaned = self.INJECTION_REGEX.sub(_quarantine_injection, raw_log)
        injection_detected = len(quarantined_payloads) > 0

        # 1. Mask emails first
        cleaned = self.EMAIL_REGEX.sub(
            lambda m: self._get_token(m.group(0), "EMAIL"),
            cleaned,
        )

        # 2. Mask IPs before bare HCNs so octets/ports don't collide
        public_ips: list[str] = []
        cleaned = self.IPV4_REGEX.sub(
            lambda m: self._handle_ip(m, public_ips),
            cleaned,
        )
        cleaned = self.IPV6_REGEX.sub(
            lambda m: self._handle_ip(m, public_ips),
            cleaned,
        )

        # 3. Mask context-prefixed HCNs (e.g. "HCN: 9876543210" or "health card 1234-567-890-YM")
        def _replace_context_hcn(match: re.Match[str]) -> str:
            prefix = match.group("prefix")
            num = match.group("num")
            if self._is_likely_hcn(num, has_context=True):
                return f"{prefix}{self._get_token(num, 'HCN')}"
            return match.group(0)

        cleaned = self.CONTEXT_HCN_REGEX.sub(_replace_context_hcn, cleaned)

        # 4. Mask remaining bare HCNs that pass formatting/Luhn checks
        def _replace_bare_hcn(match: re.Match[str]) -> str:
            num = match.group(0)
            if self._is_likely_hcn(num, has_context=False):
                return self._get_token(num, "HCN")
            return num

        cleaned = self.BARE_HCN_REGEX.sub(_replace_bare_hcn, cleaned)

        return {
            "sanitized_log": cleaned,
            "public_ips": public_ips,
            "prompt_injection_attempt": injection_detected,
            "quarantined_payloads": quarantined_payloads,
            "tokens_mapped": len(self.token_vault),
            "token_categories": dict(self.counters),
        }

    def detokenize(self, text: str) -> str:
        restored = text
        for token, original_value in self.token_vault.items():
            restored = restored.replace(token, original_value)
        return restored


if __name__ == "__main__":
    sample = (
        "2026-11-20T09:14:22Z sshd[4821]: Failed password for invalid user "
        "jsmith@nshealth.ca (HCN: 987-654-3210-YM) from 185.220.101.42 port 54321 "
        "-> dest 10.24.8.15 cgnat 100.64.12.9"
    )
    scrubber = EnterpriseLogScrubber()
    res = scrubber.sanitize_log(sample)
    print("sanitized:", res["sanitized_log"])
    print("public_ips:", res["public_ips"])
    print("restored:", scrubber.detokenize(str(res["sanitized_log"])))
