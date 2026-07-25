from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.azure.resource_facts import AzureResourceFacts, azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.resource_utils import tls_version_below_1_2
from tfstride.providers.coercion import STATE_NOT_CONFIGURED


class AzureCosmosDbRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_customer_managed_key_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for account in context.inventory.by_type(AzureResourceType.COSMOSDB_ACCOUNT):
            facts = azure_facts(account)
            if facts.cosmosdb_customer_managed_key_state != STATE_NOT_CONFIGURED:
                continue
            severity_reasoning = _data_protection_severity(key_ownership=True)
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[account.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{account.display_name} uses Microsoft-managed encryption rather than a customer-managed "
                        "Key Vault key. Cosmos DB encryption at rest remains enabled; this finding concerns customer "
                        "key ownership, rotation, and separation-of-duties controls."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(account, facts)),
                        evidence_item("encryption_ownership", _encryption_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_continuous_backup_not_configured(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for account in context.inventory.by_type(AzureResourceType.COSMOSDB_ACCOUNT):
            facts = azure_facts(account)
            backup_type = facts.cosmosdb_backup_type
            if backup_type is None or backup_type.strip().lower() == "continuous":
                continue
            severity_reasoning = _data_protection_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[account.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{account.display_name} uses effective `{backup_type}` backup rather than Continuous backup. "
                        "Periodic backup still provides recovery copies with the interval, retention, and redundancy "
                        "shown in the evidence, but it does not provide Cosmos DB continuous point-in-time recovery."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(account, facts)),
                        evidence_item("recovery_posture", _backup_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_minimum_tls_below_1_2(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for account in context.inventory.by_type(AzureResourceType.COSMOSDB_ACCOUNT):
            facts = azure_facts(account)
            tls_version = facts.cosmosdb_minimal_tls_version
            if not tls_version_below_1_2(tls_version):
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[account.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{account.display_name} sets the minimum TLS version to `{tls_version}`. Deprecated TLS "
                        "versions weaken transport protection for Cosmos DB data-plane connections."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(account, facts)),
                        evidence_item("transport_posture", [f"minimal_tls_version is {tls_version}"]),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _data_protection_severity(*, key_ownership: bool = False):
    return build_severity_reasoning(
        internet_exposure=False,
        privilege_breadth=0,
        data_sensitivity=1 if key_ownership else 2,
        lateral_movement=0,
        blast_radius=1,
    )


def _target_resource_evidence(resource: NormalizedResource, facts: AzureResourceFacts) -> list[str]:
    values = [f"address={resource.address}", f"type={resource.resource_type}"]
    if facts.cosmosdb_account_id:
        values.append(f"account_id={facts.cosmosdb_account_id}")
    if facts.cosmosdb_kind:
        values.append(f"kind={facts.cosmosdb_kind}")
    if facts.cosmosdb_offer_type:
        values.append(f"offer_type={facts.cosmosdb_offer_type}")
    return values


def _encryption_evidence(facts: AzureResourceFacts) -> list[str]:
    values = [f"customer_managed_key_state={facts.cosmosdb_customer_managed_key_state}"]
    if facts.cosmosdb_key_vault_key_id:
        values.append(f"key_vault_key_id={facts.cosmosdb_key_vault_key_id}")
    else:
        values.append("key_vault_key_id is unset")
    values.append("Cosmos DB encryption at rest remains enabled with Microsoft-managed encryption")
    return values


def _backup_evidence(facts: AzureResourceFacts) -> list[str]:
    values = [
        f"backup_configuration_state={facts.cosmosdb_backup_configuration_state or 'unknown'}",
        f"backup_block_configured is {_bool_evidence(facts.cosmosdb_backup_block_configured)}",
        f"effective_backup_type={facts.cosmosdb_backup_type or 'unknown'}",
    ]
    if facts.cosmosdb_backup_tier:
        values.append(f"backup_tier={facts.cosmosdb_backup_tier}")
    if facts.cosmosdb_backup_interval_minutes is not None:
        values.append(f"interval_in_minutes={facts.cosmosdb_backup_interval_minutes}")
    if facts.cosmosdb_backup_retention_hours is not None:
        values.append(f"retention_in_hours={facts.cosmosdb_backup_retention_hours}")
    if facts.cosmosdb_backup_storage_redundancy:
        values.append(f"storage_redundancy={facts.cosmosdb_backup_storage_redundancy}")
    return values


def _bool_evidence(value: bool | None) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    return "unknown"
