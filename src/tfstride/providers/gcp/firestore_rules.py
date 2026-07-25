from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.coercion import (
    STATE_DISABLED,
    STATE_ENABLED,
    STATE_NOT_CONFIGURED,
    STATE_UNKNOWN,
)
from tfstride.providers.gcp.resource_facts import GcpResourceFacts, gcp_facts

_FIRESTORE_DATABASE_RESOURCE_TYPE = "google_firestore_database"
_KNOWN_CONTROL_STATES = frozenset(
    {
        STATE_ENABLED,
        STATE_DISABLED,
        STATE_NOT_CONFIGURED,
        STATE_UNKNOWN,
    }
)


class GcpFirestoreRuleDetectors:
    _finding_factory: FindingFactory

    def detect_firestore_customer_managed_encryption_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for database in context.inventory.by_type(_FIRESTORE_DATABASE_RESOURCE_TYPE):
            facts = gcp_facts(database)
            if facts.firestore_cmek_state != STATE_NOT_CONFIGURED:
                continue
            severity_reasoning = _data_protection_severity(key_ownership=True)
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[database.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{database.display_name} relies on Google-managed Firestore encryption rather than "
                        "a customer-managed Cloud KMS key. Firestore remains encrypted at rest; this finding "
                        "concerns key ownership, rotation, audit separation, and compliance posture."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_evidence(database, facts)),
                        evidence_item("encryption_ownership", _encryption_evidence(database, facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_firestore_point_in_time_recovery_disabled_or_unknown(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for database in context.inventory.by_type(_FIRESTORE_DATABASE_RESOURCE_TYPE):
            facts = gcp_facts(database)
            state = _control_state(facts.firestore_pitr_state)
            if state == STATE_ENABLED:
                continue
            unknown = state == STATE_UNKNOWN
            severity_reasoning = _data_protection_severity(unknown=unknown)
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[database.address],
                    trust_boundary_id=None,
                    rationale=_pitr_rationale(database.display_name, state),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_evidence(database, facts)),
                        evidence_item("recovery_posture", _pitr_evidence(facts, state)),
                        evidence_item(
                            "posture_uncertainty",
                            _uncertainty_evidence(facts, "point_in_time_recovery_enablement"),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_firestore_delete_protection_disabled_or_unknown(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for database in context.inventory.by_type(_FIRESTORE_DATABASE_RESOURCE_TYPE):
            facts = gcp_facts(database)
            state = _control_state(facts.firestore_delete_protection_enablement)
            if state == STATE_ENABLED:
                continue
            unknown = state == STATE_UNKNOWN
            severity_reasoning = _data_protection_severity(unknown=unknown)
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[database.address],
                    trust_boundary_id=None,
                    rationale=_delete_protection_rationale(database.display_name, state),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_evidence(database, facts)),
                        evidence_item("delete_protection", _delete_protection_evidence(facts, state)),
                        evidence_item(
                            "posture_uncertainty",
                            _uncertainty_evidence(facts, "delete_protection_state"),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _data_protection_severity(*, unknown: bool = False, key_ownership: bool = False):
    return build_severity_reasoning(
        internet_exposure=False,
        privilege_breadth=0,
        data_sensitivity=1 if unknown or key_ownership else 2,
        lateral_movement=0,
        blast_radius=0 if unknown else 1,
    )


def _control_state(value: str | None) -> str:
    if value in _KNOWN_CONTROL_STATES:
        return value
    return STATE_UNKNOWN


def _target_evidence(database: NormalizedResource, facts: GcpResourceFacts) -> list[str]:
    values = [
        f"address={database.address}",
        f"resource_type={database.resource_type}",
    ]
    if database.identifier:
        values.append(f"identifier={database.identifier}")
    if facts.firestore_database_type:
        values.append(f"database_type={facts.firestore_database_type}")
    if facts.firestore_location:
        values.append(f"location={facts.firestore_location}")
    return values


def _encryption_evidence(database: NormalizedResource, facts: GcpResourceFacts) -> list[str]:
    return [
        f"cmek_state={facts.firestore_cmek_state}",
        f"kms_key_name={facts.firestore_cmek_key_name or 'unset'}",
        f"storage_encrypted={str(database.storage_encrypted).lower()}",
        "encryption_provider=Google-managed Firestore encryption",
        "finding_scope=customer-managed key ownership and control posture",
    ]


def _pitr_evidence(facts: GcpResourceFacts, state: str) -> list[str]:
    return [
        f"point_in_time_recovery_state={state}",
        f"point_in_time_recovery_enablement={facts.firestore_pitr_enablement or 'unset'}",
    ]


def _delete_protection_evidence(facts: GcpResourceFacts, state: str) -> list[str]:
    return [
        f"service_delete_protection_state={state}",
        f"delete_protection_value={facts.firestore_delete_protection_state or 'unset'}",
        f"terraform_deletion_policy={facts.firestore_terraform_deletion_policy or 'unset'}",
        (f"terraform_deletion_policy_state={facts.firestore_terraform_deletion_policy_state or STATE_UNKNOWN}"),
        "Terraform deletion policy is separate from the Firestore service delete-protection control",
    ]


def _uncertainty_evidence(facts: GcpResourceFacts, field_path: str) -> list[str]:
    return [uncertainty for uncertainty in facts.firestore_posture_uncertainties if field_path in uncertainty]


def _pitr_rationale(display_name: str, state: str) -> str:
    if state == STATE_UNKNOWN:
        return (
            f"{display_name} does not have a deterministic Firestore point-in-time recovery state in "
            "the Terraform plan. Recovery protection cannot be confirmed until the computed value is "
            "resolved."
        )
    if state == STATE_DISABLED:
        posture = "explicitly disables"
    else:
        posture = "does not configure"
    return (
        f"{display_name} {posture} Firestore point-in-time recovery. Without PITR, recovery options "
        "after accidental or malicious database changes are reduced."
    )


def _delete_protection_rationale(display_name: str, state: str) -> str:
    if state == STATE_UNKNOWN:
        return (
            f"{display_name} does not have a deterministic Firestore service delete-protection state "
            "in the Terraform plan. The service-side deletion guardrail cannot be confirmed until the "
            "computed value is resolved."
        )
    if state == STATE_DISABLED:
        posture = "explicitly disables"
    else:
        posture = "does not configure"
    return (
        f"{display_name} {posture} Firestore service delete protection. Accidental or malicious API "
        "deletion can remove the database without this additional service-side guardrail. Terraform's "
        "deletion policy is a separate lifecycle control."
    )
