from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.aws.resource_facts import AwsResourceFacts, aws_facts
from tfstride.providers.coercion import (
    STATE_DISABLED,
    STATE_ENABLED,
    STATE_NOT_CONFIGURED,
    STATE_UNKNOWN,
)

_AWS_DYNAMODB_TABLE = "aws_dynamodb_table"
_CUSTOMER_MANAGED_ENCRYPTION = "customer_managed"
_NON_CUSTOMER_MANAGED_ENCRYPTION = frozenset({"aws_owned", "aws_managed_kms"})
_KNOWN_CONTROL_STATES = frozenset(
    {
        STATE_ENABLED,
        STATE_DISABLED,
        STATE_NOT_CONFIGURED,
        STATE_UNKNOWN,
    }
)


class AwsDynamoDbRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_customer_managed_kms_key_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for table in context.inventory.by_type(_AWS_DYNAMODB_TABLE):
            facts = aws_facts(table)
            state = facts.dynamodb_encryption_ownership_state
            if state == _CUSTOMER_MANAGED_ENCRYPTION:
                continue
            unknown = state not in _NON_CUSTOMER_MANAGED_ENCRYPTION
            effective_state = STATE_UNKNOWN if unknown else state
            severity_reasoning = _data_protection_severity(unknown=unknown, key_ownership=True)
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[table.address],
                    trust_boundary_id=None,
                    rationale=_encryption_rationale(table.display_name, effective_state),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_evidence(table, facts)),
                        evidence_item(
                            "encryption_ownership",
                            _encryption_evidence(table, facts, effective_state),
                        ),
                        evidence_item(
                            "posture_uncertainty",
                            _uncertainty_evidence(facts, "server_side_encryption"),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_point_in_time_recovery_disabled_or_unknown(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for table in context.inventory.by_type(_AWS_DYNAMODB_TABLE):
            facts = aws_facts(table)
            state = _control_state(facts.dynamodb_pitr_state)
            if state == STATE_ENABLED:
                continue
            unknown = state == STATE_UNKNOWN
            severity_reasoning = _data_protection_severity(unknown=unknown)
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[table.address],
                    trust_boundary_id=None,
                    rationale=_pitr_rationale(table.display_name, state),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_evidence(table, facts)),
                        evidence_item("recovery_posture", _pitr_evidence(facts, state)),
                        evidence_item(
                            "posture_uncertainty",
                            _uncertainty_evidence(facts, "point_in_time_recovery"),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_deletion_protection_disabled_or_unknown(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for table in context.inventory.by_type(_AWS_DYNAMODB_TABLE):
            facts = aws_facts(table)
            state = _control_state(facts.dynamodb_deletion_protection_state)
            if state == STATE_ENABLED:
                continue
            unknown = state == STATE_UNKNOWN
            severity_reasoning = _data_protection_severity(unknown=unknown)
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[table.address],
                    trust_boundary_id=None,
                    rationale=_deletion_protection_rationale(table.display_name, state),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_evidence(table, facts)),
                        evidence_item(
                            "deletion_protection",
                            _deletion_protection_evidence(state),
                        ),
                        evidence_item(
                            "posture_uncertainty",
                            _uncertainty_evidence(facts, "deletion_protection_enabled"),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _data_protection_severity(*, unknown: bool, key_ownership: bool = False):
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


def _target_evidence(table: NormalizedResource, facts: AwsResourceFacts) -> list[str]:
    values = [
        f"address={table.address}",
        f"resource_type={table.resource_type}",
    ]
    if table.identifier:
        values.append(f"identifier={table.identifier}")
    if facts.dynamodb_table_arn:
        values.append(f"table_arn={facts.dynamodb_table_arn}")
    return values


def _encryption_evidence(
    table: NormalizedResource,
    facts: AwsResourceFacts,
    state: str,
) -> list[str]:
    return [
        f"encryption_ownership_state={state}",
        (f"encryption_configuration_state={facts.dynamodb_encryption_configuration_state or STATE_UNKNOWN}"),
        f"kms_key_arn={facts.dynamodb_kms_key_arn or 'unset'}",
        f"storage_encrypted={str(table.storage_encrypted).lower()}",
        "finding_scope=customer-managed key ownership and control posture",
        "DynamoDB remains encrypted at rest when an AWS-owned or AWS-managed key is used",
    ]


def _pitr_evidence(facts: AwsResourceFacts, state: str) -> list[str]:
    values = [f"point_in_time_recovery_state={state}"]
    if facts.dynamodb_pitr_recovery_period_days is not None:
        values.append(f"recovery_period_in_days={facts.dynamodb_pitr_recovery_period_days}")
    else:
        values.append("recovery_period_in_days=unset")
    return values


def _deletion_protection_evidence(state: str) -> list[str]:
    return [f"deletion_protection_state={state}"]


def _uncertainty_evidence(facts: AwsResourceFacts, field_path: str) -> list[str]:
    return [uncertainty for uncertainty in facts.dynamodb_posture_uncertainties if field_path in uncertainty]


def _encryption_rationale(display_name: str, state: str | None) -> str:
    if state == STATE_UNKNOWN:
        return (
            f"{display_name} does not show deterministic customer-managed KMS encryption in the "
            "Terraform plan. DynamoDB remains encrypted at rest, but key ownership, rotation, audit "
            "separation, and compliance posture cannot be confirmed."
        )
    key_description = "an AWS-owned key" if state == "aws_owned" else "the AWS-managed DynamoDB KMS key"
    return (
        f"{display_name} uses {key_description} rather than a customer-managed KMS key. DynamoDB "
        "remains encrypted at rest; this finding concerns key ownership, rotation, audit separation, "
        "and compliance posture."
    )


def _pitr_rationale(display_name: str, state: str) -> str:
    if state == STATE_UNKNOWN:
        return (
            f"{display_name} does not have a deterministic DynamoDB point-in-time recovery state in "
            "the Terraform plan. Recovery protection cannot be confirmed until the computed value is "
            "resolved."
        )
    if state == STATE_DISABLED:
        posture = "explicitly disables"
    else:
        posture = "does not configure"
    return (
        f"{display_name} {posture} DynamoDB point-in-time recovery. Without PITR, recovery options "
        "after accidental or malicious table data changes are reduced."
    )


def _deletion_protection_rationale(display_name: str, state: str) -> str:
    if state == STATE_UNKNOWN:
        return (
            f"{display_name} does not have a deterministic DynamoDB deletion protection state in the "
            "Terraform plan. The control-plane deletion guardrail cannot be confirmed until the "
            "computed value is resolved."
        )
    if state == STATE_DISABLED:
        posture = "explicitly disables"
    else:
        posture = "does not configure"
    return (
        f"{display_name} {posture} DynamoDB deletion protection. Accidental or malicious delete "
        "operations can remove the table without this additional control-plane guardrail."
    )
