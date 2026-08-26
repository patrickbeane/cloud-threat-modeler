from __future__ import annotations

import unittest
from copy import deepcopy
from typing import Any

from tests.providers.azure.test_azure_app_service_key_vault_operation_paths import (
    _KEY_VERSIONLESS_RESOURCE_ID,
    _KEY_VERSIONLESS_URI,
    _SERVICE_ENCRYPTION_USER_ID,
    _SUBSCRIPTION_SCOPE,
    _SYSTEM_PRINCIPAL_ID,
    _USER_PRINCIPAL_ID,
    _VAULT_ID,
    _VAULT_URI,
    _access_policy,
    _function_app,
    _key,
    _resource,
    _role_assignment,
    _user_assigned_identity,
    _vault,
    _web_app,
)
from tests.providers.azure.test_azure_app_service_key_vault_protected_data_convergence import (
    _AZURE_KEY_VERSIONLESS_URI as _PROTECTED_DATA_KEY_VERSIONLESS_URI,
)
from tests.providers.azure.test_azure_app_service_key_vault_protected_data_convergence import (
    _azure_resources as _protected_data_resources,
)
from tests.providers.azure.test_azure_app_service_key_vault_protected_data_convergence import (
    _versionless_storage_resources as _versionless_protected_data_resources,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _symbolic_resolution as _storage_symbolic_resolution,
)
from tests.providers.azure.test_azure_public_app_service_storage_mutation_rules import _public
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import StrideCategory, TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS

_DECRYPT_RULE = "azure-public-app-service-key-vault-decrypt-access"
_SIGN_RULE = "azure-public-app-service-key-vault-signing-access"


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = AzureNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or {_DECRYPT_RULE, _SIGN_RULE})),
    )


def _evidence(finding: Any) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


def _key_named(
    name: str,
    *,
    key_opts: tuple[str, ...] = ("decrypt", "unwrapKey", "sign"),
    version: str | None = "v-001",
) -> TerraformResource:
    versionless_uri = f"{_VAULT_URI}/keys/{name}"
    versionless_resource_id = f"{_VAULT_ID}/keys/{name}"
    values: dict[str, object] = {
        "versionless_id": versionless_uri,
        "resource_versionless_id": versionless_resource_id,
        "name": name,
        "key_vault_id": "azurerm_key_vault.orders.id",
        "key_type": "RSA-HSM",
        "key_opts": list(key_opts),
    }
    if version is not None:
        values.update(
            {
                "id": f"{versionless_uri}/{version}",
                "resource_id": f"{versionless_resource_id}/{version}",
                "version": version,
            }
        )
    return _resource(AzureResourceType.KEY_VAULT_KEY, name, values)


def _two_storage_container_protected_data_resources() -> list[TerraformResource]:
    resources = _protected_data_resources()
    container = next(resource for resource in resources if resource.address == "azurerm_storage_container.orders")
    role_assignment = next(
        resource for resource in resources if resource.address == "azurerm_role_assignment.orders_blob"
    )
    second_container = deepcopy(container)
    second_container.address = "azurerm_storage_container.archive"
    second_container.name = "archive"
    second_container.values["name"] = "archive"
    second_container.values["id"] = str(second_container.values["id"]).replace("/orders", "/archive")
    second_role_assignment = deepcopy(role_assignment)
    second_role_assignment.address = "azurerm_role_assignment.archive_blob"
    second_role_assignment.name = "archive_blob"
    archive_scope = "azurerm_storage_container.archive.resource_manager_id"
    second_role_assignment.values["scope"] = None
    second_role_assignment.unknown_values["scope"] = True
    second_role_assignment.reference_resolutions = (_storage_symbolic_resolution(("scope",), archive_scope),)
    resources.extend([second_container, second_role_assignment])
    return resources


class AzurePublicAppServiceKeyVaultOperationRuleTests(unittest.TestCase):
    def test_rules_are_registered(self) -> None:
        registered = {rule_id for group in AZURE_RULE_GROUP_IDS for rule_id in group}
        self.assertIn(_DECRYPT_RULE, registered)
        self.assertIn(_SIGN_RULE, registered)

    def test_public_system_identity_emits_separate_decrypt_and_signing_findings(self) -> None:
        findings = _evaluate(
            [
                _vault(rbac_enabled=True),
                _key(),
                _public(_web_app()),
                _role_assignment(scope="azurerm_key_vault.orders.id"),
            ],
            _DECRYPT_RULE,
            _SIGN_RULE,
        )

        self.assertEqual({finding.rule_id for finding in findings}, {_DECRYPT_RULE, _SIGN_RULE})
        by_rule = {finding.rule_id: finding for finding in findings}
        decrypt = by_rule[_DECRYPT_RULE]
        signing = by_rule[_SIGN_RULE]
        self.assertEqual(decrypt.category, StrideCategory.INFORMATION_DISCLOSURE)
        self.assertEqual(signing.category, StrideCategory.SPOOFING)
        assert decrypt.severity_reasoning is not None
        assert signing.severity_reasoning is not None
        self.assertEqual(decrypt.severity_reasoning.data_sensitivity, 2)
        self.assertEqual(signing.severity_reasoning.data_sensitivity, 1)
        self.assertEqual(decrypt.severity_reasoning.blast_radius, 2)
        self.assertEqual(signing.severity_reasoning.blast_radius, 2)
        self.assertIn("deterministic Key Vault decrypt and unwrap authority", decrypt.rationale)
        self.assertIn("decrypt and unwrap operations", decrypt.rationale)
        self.assertIn("deterministic Key Vault signing authority", signing.rationale)
        self.assertIn("accepted by a relying application", signing.rationale)
        self.assertEqual(
            decrypt.affected_resources,
            [
                "azurerm_linux_web_app.orders",
                "azurerm_key_vault.orders",
                "azurerm_key_vault_key.signing",
                "azurerm_role_assignment.key_access",
            ],
        )
        evidence = _evidence(decrypt)
        self.assertIn("public_network_access_enabled=true", evidence["public_endpoint"])
        self.assertTrue(
            any(
                "identity_kind=system_assigned" in value
                and f"principal_id={_SYSTEM_PRINCIPAL_ID}" in value
                and "credential_context=workload_runtime" in value
                for value in evidence["runtime_identity"]
            )
        )
        path = evidence["key_vault_operation_paths"][0]
        self.assertIn("operation=decrypt", path)
        self.assertIn("operation_class=plaintext_recovery", path)
        self.assertIn("authorization_model=azure_rbac", path)
        self.assertIn("scope_type=vault", path)
        self.assertIn("key_uri=https://orders.vault.azure.net/keys/signing/v-001", path)
        self.assertIn(f"key_versionless_uri={_KEY_VERSIONLESS_URI}", path)
        self.assertIn(
            "subscription_grants=0; resource_group_grants=0; vault_grants=1; exact_key_grants=0; "
            "parent_scope_grants=1; modeled_keys=1; broadest_scope=vault; out_of_plan_keys_not_modeled=true; "
            "blast_radius_basis=parent_scope_grant",
            evidence["scope_breadth"],
        )

    def test_decrypt_enrichment_preserves_operations_and_logical_dependency_counts(self) -> None:
        findings = _evaluate(_protected_data_resources(), _DECRYPT_RULE)

        self.assertEqual([finding.rule_id for finding in findings], [_DECRYPT_RULE])
        finding = findings[0]
        assert finding.severity_reasoning is not None
        self.assertIn("azurerm_storage_container.orders", finding.affected_resources)
        self.assertIn(
            "converges with 1 unique Key Vault-protected Storage or Service Bus resource(s) across "
            "1 unique encryption dependency relationship(s)",
            finding.rationale,
        )
        evidence = _evidence(finding)
        self.assertEqual(
            {value.split("operation=", 1)[1].split(";", 1)[0] for value in evidence["key_vault_operation_paths"]},
            {"decrypt", "unwrap"},
        )
        self.assertIn(
            "unique_dependency_count=1; unique_dependent_resource_count=1; "
            "downstream_dependency_state=resolved_dependents",
            evidence["downstream_dependencies"],
        )
        self.assertTrue(
            any(
                "protected_resource_addresses=azurerm_storage_container.orders" in value
                and "operations=decrypt,unwrap" in value
                and "authorization_proof_count=1" in value
                for value in evidence["downstream_dependencies"]
            )
        )

    def test_multiple_protected_resources_raise_downstream_blast_radius(self) -> None:
        findings = _evaluate(_two_storage_container_protected_data_resources(), _DECRYPT_RULE)

        self.assertEqual([finding.rule_id for finding in findings], [_DECRYPT_RULE])
        finding = findings[0]
        assert finding.severity_reasoning is not None
        self.assertEqual(finding.severity_reasoning.blast_radius, 2)
        self.assertIn("azurerm_storage_container.orders", finding.affected_resources)
        self.assertIn("azurerm_storage_container.archive", finding.affected_resources)
        evidence = _evidence(finding)
        self.assertIn(
            "unique_dependency_count=1; unique_dependent_resource_count=2; "
            "downstream_dependency_state=resolved_dependents",
            evidence["downstream_dependencies"],
        )
        dependency_lines = [
            value for value in evidence["downstream_dependencies"] if value.startswith("protected_resource_addresses=")
        ]
        self.assertEqual(len(dependency_lines), 1)
        self.assertIn(
            "protected_resource_addresses=azurerm_storage_container.archive,azurerm_storage_container.orders",
            dependency_lines[0],
        )
        self.assertIn("operations=decrypt,unwrap", dependency_lines[0])
        self.assertIn("authorization_proof_count=1", dependency_lines[0])

    def test_versionless_dependency_enriches_plaintext_recovery_without_claiming_a_version(self) -> None:
        findings = _evaluate(_versionless_protected_data_resources(), _DECRYPT_RULE)

        self.assertEqual([finding.rule_id for finding in findings], [_DECRYPT_RULE])
        finding = findings[0]
        self.assertIn("azurerm_storage_container.orders", finding.affected_resources)
        evidence = _evidence(finding)
        self.assertEqual(
            {value.split("operation=", 1)[1].split(";", 1)[0] for value in evidence["key_vault_operation_paths"]},
            {"decrypt", "unwrap"},
        )
        self.assertIn(
            "unique_dependency_count=1; unique_dependent_resource_count=1; "
            "downstream_dependency_state=resolved_dependents",
            evidence["downstream_dependencies"],
        )
        self.assertTrue(
            any(
                "protected_resource_addresses=azurerm_storage_container.orders" in value
                and "key_uri=none" in value
                and f"key_versionless_uri={_PROTECTED_DATA_KEY_VERSIONLESS_URI}" in value
                and "operations=decrypt,unwrap" in value
                for value in evidence["downstream_dependencies"]
            )
        )

    def test_unwrap_only_path_does_not_claim_decrypt_authority(self) -> None:
        findings = _evaluate(
            [
                _vault(rbac_enabled=True),
                _key(key_opts=("unwrapKey",)),
                _public(_web_app()),
                _role_assignment(
                    role_id=_SERVICE_ENCRYPTION_USER_ID,
                    role_name="Key Vault Crypto Service Encryption User",
                ),
            ],
            _DECRYPT_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_DECRYPT_RULE])
        finding = findings[0]
        self.assertIn("deterministic Key Vault unwrap authority", finding.rationale)
        self.assertNotIn("decrypt and unwrap authority", finding.rationale)
        scope = _evidence(finding)["authorization_scope"]
        self.assertTrue(any("establishes=deterministic Key Vault unwrap authority" in value for value in scope))
        self.assertNotIn("decrypt and unwrap authority", scope)
        self.assertTrue(any("operation=unwrap" in value for value in _evidence(finding)["key_vault_operation_paths"]))

    def test_parent_scope_grant_reports_modeled_fanout_without_claiming_inventory(self) -> None:
        findings = _evaluate(
            [
                _vault(rbac_enabled=True),
                _key_named("decrypt", key_opts=("decrypt",)),
                _key_named("secondary", key_opts=("decrypt",)),
                _public(_web_app()),
                _role_assignment(scope=_SUBSCRIPTION_SCOPE),
            ],
            _DECRYPT_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_DECRYPT_RULE])
        finding = findings[0]
        assert finding.severity_reasoning is not None
        self.assertEqual(finding.severity_reasoning.blast_radius, 2)
        self.assertIn("broader than an exact-key grant", finding.rationale)
        self.assertIn("not an inventory of every out-of-plan key", finding.rationale)
        evidence = _evidence(finding)
        self.assertEqual(len(evidence["key_vault_operation_paths"]), 2)
        self.assertIn(
            "subscription_grants=1; resource_group_grants=0; vault_grants=0; exact_key_grants=0; "
            "parent_scope_grants=1; modeled_keys=2; broadest_scope=subscription; out_of_plan_keys_not_modeled=true; "
            "blast_radius_basis=parent_scope_grant",
            evidence["scope_breadth"],
        )

    def test_exact_key_scope_has_narrower_blast_radius(self) -> None:
        findings = _evaluate(
            [
                _vault(rbac_enabled=True),
                _key(key_opts=("decrypt",)),
                _public(_web_app()),
                _role_assignment(scope="azurerm_key_vault_key.signing.resource_versionless_id"),
            ],
            _DECRYPT_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_DECRYPT_RULE])
        finding = findings[0]
        assert finding.severity_reasoning is not None
        self.assertEqual(finding.severity_reasoning.blast_radius, 1)
        evidence = _evidence(finding)
        self.assertIn(
            "subscription_grants=0; resource_group_grants=0; vault_grants=0; exact_key_grants=1; "
            "parent_scope_grants=0; modeled_keys=1; broadest_scope=key; "
            "out_of_plan_keys_not_modeled=true; blast_radius_basis=exact_key_grant",
            evidence["scope_breadth"],
        )
        self.assertIn(f"scope_arm_id={_KEY_VERSIONLESS_RESOURCE_ID}", evidence["key_vault_operation_paths"][0])

    def test_user_assigned_runtime_identity_uses_application_authority(self) -> None:
        findings = _evaluate(
            [
                _vault(),
                _key(key_opts=("decrypt",)),
                _user_assigned_identity(),
                _public(_function_app()),
                _access_policy(
                    principal_id=_USER_PRINCIPAL_ID,
                    key_permissions=("Decrypt",),
                ),
            ],
            _DECRYPT_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_DECRYPT_RULE])
        finding = findings[0]
        self.assertIn("azurerm_user_assigned_identity.orders_runtime", finding.affected_resources)
        self.assertIn("azurerm_key_vault_access_policy.runtime", finding.affected_resources)
        self.assertTrue(
            any(
                "identity_kind=user_assigned" in value and f"principal_id={_USER_PRINCIPAL_ID}" in value
                for value in _evidence(finding)["runtime_identity"]
            )
        )

    def test_versionless_key_identity_remains_distinct_in_finding_evidence(self) -> None:
        findings = _evaluate(
            [
                _vault(),
                _key(key_opts=("decrypt",), version=None),
                _public(_web_app()),
                _access_policy(
                    principal_id=_SYSTEM_PRINCIPAL_ID,
                    key_permissions=("Decrypt",),
                ),
            ],
            _DECRYPT_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_DECRYPT_RULE])
        path = _evidence(findings[0])["key_vault_operation_paths"][0]
        self.assertIn("key_uri=none", path)
        self.assertIn(f"key_versionless_uri={_KEY_VERSIONLESS_URI}", path)
        self.assertIn("key_resource_id=none", path)
        self.assertIn(f"key_versionless_resource_id={_KEY_VERSIONLESS_RESOURCE_ID}", path)
        self.assertIn("key_version=none", path)

    def test_private_and_quiet_key_capabilities_stay_silent(self) -> None:
        self.assertEqual(
            _evaluate(
                [
                    _vault(rbac_enabled=True),
                    _key(key_opts=("decrypt",)),
                    _web_app(),
                    _role_assignment(),
                ],
                _DECRYPT_RULE,
            ),
            [],
        )
        self.assertEqual(
            _evaluate(
                [
                    _vault(rbac_enabled=True),
                    _key(key_opts=("encrypt",)),
                    _public(_web_app()),
                    _role_assignment(),
                ],
                _DECRYPT_RULE,
            ),
            [],
        )
        self.assertEqual(
            _evaluate(
                [
                    _vault(rbac_enabled=True),
                    _key(key_opts=("decrypt",)),
                    _public(_web_app()),
                    _role_assignment(),
                ],
                _SIGN_RULE,
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
