"""Score each active rule once per assessment, in a deterministic order."""

from dataclasses import dataclass
from collections.abc import Iterable

from .config import Settings

RULE_NAMES = ("port_scan", "syn_flood", "traffic_anomaly")


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    severity: str | None
    rules: tuple[str, ...]


def score_rules(rules: Iterable[str], settings: Settings) -> RiskAssessment:
    unique = set(rules)
    if unique - set(RULE_NAMES):
        raise ValueError("Unknown detection rule")
    ordered = tuple(rule for rule in RULE_NAMES if rule in unique)
    score = sum(settings.risk_weights[rule] for rule in ordered)
    severity = None
    for level in ("low", "medium", "high", "critical"):
        if score >= settings.severity_min_scores[level]:
            severity = level.capitalize()
    return RiskAssessment(score, severity, ordered)
