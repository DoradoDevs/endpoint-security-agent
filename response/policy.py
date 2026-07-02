"""
Sentinel Agent — Response Policy

Maps SecurityProfile to ResponseLevel and determines what auto-responses
are allowed based on the current configuration.
"""

from __future__ import annotations

from core.config import AgentConfig, Severity
from response.models import ResponseLevel


# Maps profile names to response aggressiveness
PROFILE_RESPONSE_LEVELS: dict[str, ResponseLevel] = {
    "minimal": ResponseLevel.ALERT_ONLY,
    "standard": ResponseLevel.LOG_AND_ALERT,
    "strict": ResponseLevel.PROMPT,
    "fort_knox": ResponseLevel.AUTO_RESPOND,
}


class ResponsePolicy:
    """Determines what response actions are permitted based on profile."""

    def __init__(self, config: AgentConfig):
        self.config = config
        profile_name = getattr(config, "profile", "standard")
        self.level = PROFILE_RESPONSE_LEVELS.get(
            profile_name, ResponseLevel.LOG_AND_ALERT
        )

    def should_auto_respond(self) -> bool:
        return self.level == ResponseLevel.AUTO_RESPOND

    def should_prompt(self) -> bool:
        return self.level == ResponseLevel.PROMPT

    def is_response_allowed(self) -> bool:
        """Check if active responses (beyond alerting) are allowed."""
        return self.level in (ResponseLevel.PROMPT, ResponseLevel.AUTO_RESPOND)

    def min_severity_for_response(self) -> Severity:
        """What's the minimum severity that triggers a response."""
        if self.level == ResponseLevel.AUTO_RESPOND:
            return Severity.MEDIUM
        return Severity.HIGH
