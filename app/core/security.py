import re
from typing import Dict, List, Tuple

# Role hierarchy: higher roles inherit access to lower classification levels
ROLE_PERMISSIONS: Dict[str, List[str]] = {
    "guest": ["public"],
    "employee": ["public", "internal"],
    "executive": ["public", "internal", "confidential"],
    "compliance_officer": ["public", "internal", "confidential"],
}

# Known prompt injection signatures & jailbreak patterns
PROMPT_INJECTION_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?(previous|prior)\s+(instructions|directives|rules)",
    r"(?i)disregard\s+(the\s+)?above",
    r"(?i)you\s+are\s+now\s+(DAN|unfiltered|jailbroken|an\s+adversary)",
    r"(?i)system\s+prompt\s+(reveal|leak|output|dump)",
    r"(?i)forget\s+everything\s+you\s+know",
    r"(?i)bypass\s+(security|safety|content\s+filter)",
    r"(?i)act\s+as\s+a\s+root\s+user",
    r"(?i)print\s+your\s+initial\s+prompt",
]

# Australian PII regex patterns
AU_PHONE_PATTERN = r"(?:\+?61\s?|0)[2-478](?:[ -]?\d){8}"
EMAIL_PATTERN = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
AU_TFN_PATTERN = r"\b\d{3}\s?\d{3}\s?\d{3}\b"
CREDIT_CARD_PATTERN = r"\b(?:\d{4}[ -]?){3}\d{4}\b"

class SecurityEngine:
    """Enterprise security gatekeeper for AI pipelines."""

    @staticmethod
    def inspect_prompt_injection(user_input: str) -> Tuple[bool, str]:
        """
        Scans incoming prompt for injection, override, or jailbreak attempts.
        Returns: (is_safe: bool, reason: str)
        """
        for pattern in PROMPT_INJECTION_PATTERNS:
            match = re.search(pattern, user_input)
            if match:
                return False, f"Flagged adversarial pattern: '{match.group(0)}'"
        return True, "Passed injection inspection"

    @staticmethod
    def redact_pii(text: str) -> Tuple[str, List[str]]:
        """
        Redacts personally identifiable information (PII) including
        Australian phone numbers, emails, and financial identifiers.
        Returns: (sanitized_text, list_of_redacted_types)
        """
        redactions = []
        sanitized = text

        if re.search(AU_PHONE_PATTERN, sanitized):
            sanitized = re.sub(AU_PHONE_PATTERN, "[REDACTED_AU_PHONE]", sanitized)
            redactions.append("AU Phone Number")

        if re.search(EMAIL_PATTERN, sanitized):
            sanitized = re.sub(EMAIL_PATTERN, "[REDACTED_EMAIL]", sanitized)
            redactions.append("Email Address")

        if re.search(CREDIT_CARD_PATTERN, sanitized):
            sanitized = re.sub(CREDIT_CARD_PATTERN, "[REDACTED_PAYMENT_CARD]", sanitized)
            redactions.append("Payment Card")

        return sanitized, redactions

    @staticmethod
    def get_allowed_classifications(user_role: str) -> List[str]:
        """
        Retrieves the document security classifications a given role is authorized to query.
        """
        normalized_role = user_role.lower().strip()
        return ROLE_PERMISSIONS.get(normalized_role, ["public"])

    @staticmethod
    def build_rbac_filter(user_role: str) -> dict:
        """
        Constructs a ChromaDB-compatible query filter based on the user's role.
        """
        allowed = SecurityEngine.get_allowed_classifications(user_role)
        if len(allowed) == 1:
            return {"classification": allowed[0]}
        return {"classification": {"$in": allowed}}
