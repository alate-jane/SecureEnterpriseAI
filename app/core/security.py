import re
from typing import Dict, List, Tuple, Optional

# Role hierarchy: higher roles inherit access to lower classification levels
ROLE_PERMISSIONS: Dict[str, List[str]] = {
    "guest": ["public"],
    "employee": ["public", "internal"],
    "executive": ["public", "internal", "confidential"],
    "compliance_officer": ["public", "internal", "confidential"],
    "admin": ["public", "internal", "confidential"],
}

# Pre-seeded enterprise demo users
USERS_DB: Dict[str, dict] = {
    "guest_user": {
        "username": "guest_user",
        "display_name": "Guest Visitor",
        "password": "guest123",
        "role": "guest"
    },
    "emp_jane": {
        "username": "emp_jane",
        "display_name": "Jane Developer",
        "password": "emp123",
        "role": "employee"
    },
    "exec_sarah": {
        "username": "exec_sarah",
        "display_name": "Sarah Executive",
        "password": "exec123",
        "role": "executive"
    },
    "admin_boss": {
        "username": "admin_boss",
        "display_name": "System Administrator",
        "password": "admin123",
        "role": "admin"
    }
}

import hmac
import hashlib
import json
import base64
import time

SECRET_KEY = "enterprise-secure-ai-secret-key-2026"

def create_access_token(username: str, role: str) -> str:
    """Generates a signed URL-safe bearer token."""
    payload = {
        "sub": username,
        "role": role,
        "exp": int(time.time()) + 86400  # 24 hours
    }
    encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signature = hmac.new(SECRET_KEY.encode(), encoded_payload.encode(), hashlib.sha256).hexdigest()
    return f"{encoded_payload}.{signature}"

def verify_access_token(token: str) -> Optional[dict]:
    """Validates signature and expiration of bearer token."""
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        encoded_payload, sig = parts
        expected_sig = hmac.new(SECRET_KEY.encode(), encoded_payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        padding = 4 - (len(encoded_payload) % 4)
        if padding != 4:
            encoded_payload += "=" * padding
        payload = json.loads(base64.urlsafe_b64decode(encoded_payload.encode()).decode())
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None

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
