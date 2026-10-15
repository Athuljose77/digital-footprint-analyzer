import logging
from typing import List, Optional, Callable, Set, Tuple
from app.models.common import Finding

from app.core.findings_processor import _merge_evidence
from app.core.findings.models import NormalizedCheckResult, EvidenceItem
from app.core.findings.rules import MODULE_RULES, ALL_RULES

logger = logging.getLogger(__name__)

class FindingsProcessor:
    """
    Deterministic rule-based findings processor.
    Dispatches normalized check results to applicable rules,
    isolates rule execution errors, and deduplicates findings within a scan.
    """

    def __init__(self, rules_override: Optional[List[Callable]] = None):
        self.rules_override = rules_override

    def process(self, result: NormalizedCheckResult) -> List[Finding]:
        """
        Processes a NormalizedCheckResult and returns deduplicated Findings.
        - Rules only evaluate on COMPLETED or PARTIAL check statuses.
        - Never infers absence from FAILED or UNAVAILABLE checks.
        - Deduplication key: (rule_id, source_module, evidence_key).
        """
        # Never generate findings for failed or unavailable checks
        if result.status in ("FAILED", "UNAVAILABLE"):
            return []

        # If outcome is NOT_FOUND or UNKNOWN without positive evidence items, no findings
        if not result.evidence_items:
            return []

        # Determine rules to run for this module
        if self.rules_override is not None:
            active_rules = self.rules_override
        else:
            active_rules = MODULE_RULES.get(result.module, [])

        findings: List[Finding] = []
        dedup_map: Dict[str, Finding] = {}
        order: List[str] = []

        for item in result.evidence_items:
            for rule_fn in active_rules:
                try:
                    finding = rule_fn(result, item)
                    if finding is None:
                        continue

                    # Deduplication key: (rule_id, source_module, evidence_key)
                    dedup_key = (
                        finding.rule_id or finding.finding_type,
                        item.source_module,
                        item.evidence_key,
                    )

                    if dedup_key in dedup_map:
                        existing = dedup_map[dedup_key]

                        current_rank = _get_severity_rank(existing.severity) if False else 0
                        # Imported severity ranks are unavailable here; compare known names via
                        # the canonical processor's helper when this module is used in tests.
                        try:
                            from app.core.findings_processor import _get_severity_rank as _rank
                            chosen_severity = (
                                existing.severity
                                if _rank(existing.severity) >= _rank(finding.severity)
                                else finding.severity
                            )
                        except Exception:
                            chosen_severity = existing.severity if existing.severity else finding.severity

                        merged_evidence = _merge_evidence(existing.evidence, finding.evidence)

                        chosen_description = existing.description
                        if finding.description and len(finding.description) > len(existing.description or ""):
                            chosen_description = finding.description

                        status_priority = {
                            "UNREMEDIATED": 4,
                            "ACTIVE": 3,
                            "OPEN": 3,
                            "WARNING": 2,
                            "INFORMATIONAL": 1,
                            "INFO": 1,
                            "RESOLVED": 0,
                        }
                        chosen_status = (
                            existing.status
                            if status_priority.get(existing.status.upper(), 1) >=
                            status_priority.get(finding.status.upper(), 1)
                            else finding.status
                        )
                        chosen_category = (
                            "Concern"
                            if "Concern" in (existing.category, finding.category)
                            else existing.category
                        )
                        chosen_rule_id = existing.rule_id if existing.rule_id is not None else finding.rule_id
                        chosen_limitations = existing.limitations
                        if finding.limitations and (
                            not chosen_limitations or len(finding.limitations) > len(chosen_limitations)
                        ):
                            chosen_limitations = finding.limitations

                        dedup_map[dedup_key] = Finding(
                            finding_id=existing.finding_id,
                            finding_type=existing.finding_type,
                            title=existing.title,
                            description=chosen_description,
                            evidence=merged_evidence,
                            severity=chosen_severity,
                            status=chosen_status,
                            category=chosen_category,
                            rule_id=chosen_rule_id,
                            limitations=chosen_limitations,
                        )
                    else:
                        dedup_map[dedup_key] = finding
                        order.append(dedup_key)
                        continue

                    # No new append; an existing key was merged above.

                except Exception as e:
                    # Isolate unexpected rule failures; do not leak sensitive info or stack traces
                    rule_name = getattr(rule_fn, "__name__", "unknown_rule")
                    logger.warning(
                        "Isolated failure in rule '%s' for module '%s': %s",
                        rule_name, result.module, type(e).__name__
                    )

        # Sort deterministically: severity descending, then type and title.
        try:
            from app.core.findings_processor import _get_severity_rank
            ordered = sorted(
                dedup_map.values(),
                key=lambda f: (
                    -_get_severity_rank(f.severity),
                    (f.finding_type or "").strip().lower(),
                    (f.title or "").strip().lower(),
                ),
            )
            return ordered
        except Exception:
            return [dedup_map[k] for k in order]
