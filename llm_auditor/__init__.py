"""Auditoria pós-experimento das decisões multi-domínio do CoMAS."""

from .core import (
    audit_run,
    compare_verdicts,
    extract_decision_events,
    group_decision_events,
)
from .ollama import OllamaAuditClient, OllamaAuditError

__all__ = [
    "OllamaAuditClient",
    "OllamaAuditError",
    "audit_run",
    "compare_verdicts",
    "extract_decision_events",
    "group_decision_events",
]
