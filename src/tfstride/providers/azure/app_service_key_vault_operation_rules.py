from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import (
    AZURE_APP_SERVICE_RESOURCE_TYPES,
    AzureResourceType,
)

_DECRYPT_OPERATION = "decrypt"
_DECRYPT_OPERATIONS = frozenset({"decrypt", "unwrap"})
_SIGN_OPERATION = "sign"
_SUPPORTED_SCOPE_TYPES = frozenset({"subscription", "resource_group", "vault", "key"})
_PARENT_SCOPE_TYPES = frozenset({"subscription", "resource_group", "vault"})
_ACCESS_POLICY_SOURCE_TYPES = frozenset({AzureResourceType.KEY_VAULT, AzureResourceType.KEY_VAULT_ACCESS_POLICY})
_VAULT_ID_PATTERN = re.compile(
    r"^(?P<subscription>/subscriptions/[^/]+)"
    r"(?P<resource_group>/resourceGroups/[^/]+)"
    r"/providers/Microsoft\.KeyVault/vaults/[^/]+$",
    re.IGNORECASE,
)


class AzureAppServiceKeyVaultOperationRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_app_service_key_vault_decrypt_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_public_operation_access(context, rule_id, _DECRYPT_OPERATION)

    def detect_public_app_service_key_vault_signing_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_public_operation_access(context, rule_id, _SIGN_OPERATION)

    def _detect_public_operation_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
        operation_class: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            facts = azure_facts(app)
            if facts.public_network_access_enabled is not True:
                continue

            paths = [
                path
                for path in facts.app_service_key_vault_operation_paths
                if _is_deterministic_operation_path(path, app, context, operation_class)
            ]
            if not paths:
                continue

            key_addresses = _path_values(paths, "key_address")
            vault_addresses = _path_values(paths, "key_vault_address")
            identity_addresses = _path_values(paths, "identity_address")
            grant_addresses = _path_values(paths, "grant_source_address")
            role_definition_addresses = _path_values(paths, "role_definition_address")
            operations = _path_operations(paths)
            parent_scope = any(path.get("scope_type") in _PARENT_SCOPE_TYPES for path in paths)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=1,
                data_sensitivity=2 if operation_class == _DECRYPT_OPERATION else 1,
                lateral_movement=1,
                blast_radius=2 if parent_scope else 1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            app.address,
                            *(address for address in identity_addresses if address != app.address),
                            *vault_addresses,
                            *key_addresses,
                            *grant_addresses,
                            *role_definition_addresses,
                        ]
                    ),
                    trust_boundary_id=None,
                    rationale=_rationale(
                        app,
                        operation_class,
                        operations,
                        key_addresses,
                        parent_scope=parent_scope,
                    ),
                    evidence=collect_evidence(
                        evidence_item("public_endpoint", _public_endpoint_evidence(app)),
                        evidence_item("runtime_identity", _runtime_identity_evidence(paths)),
                        evidence_item("key_vault_operation_paths", _operation_path_evidence(paths)),
                        evidence_item("scope_breadth", _scope_breadth_evidence(paths)),
                        evidence_item(
                            "authorization_scope",
                            _authorization_scope(operation_class, operations, parent_scope),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _is_deterministic_operation_path(
    path: Mapping[str, Any],
    app: NormalizedResource,
    context: RuleEvaluationContext,
    operation_class: str,
) -> bool:
    operation = _known_string(path.get("operation"))
    if operation_class == _DECRYPT_OPERATION:
        if operation not in _DECRYPT_OPERATIONS or path.get("operation_class") != "plaintext_recovery":
            return False
        expected_key_operation = "decrypt" if operation == "decrypt" else "unwrapKey"
    else:
        if operation != _SIGN_OPERATION or path.get("operation_class") != "authenticator_generation":
            return False
        expected_key_operation = "sign"

    if (
        path.get("workload_address") != app.address
        or path.get("workload_type") != app.resource_type
        or path.get("identity_kind") not in {"system_assigned", "user_assigned"}
        or path.get("credential_context") != "workload_runtime"
        or path.get("key_resource_type") != AzureResourceType.KEY_VAULT_KEY
        or path.get("authorization_state") != "granted"
        or path.get("authorization_model_state") != "active"
        or path.get("condition_state") != "not_configured"
        or path.get("condition") is not None
        or path.get("grant_kind") not in {"access_policy", "rbac"}
        or path.get("evaluation_basis") != "modeled_key_vault_key_authorization"
        or path.get("scope_type") not in _SUPPORTED_SCOPE_TYPES
        or path.get("matched_key_operation") != expected_key_operation
    ):
        return False

    identity_address = _known_string(path.get("identity_address"))
    principal_id = _known_string(path.get("principal_id"))
    key_address = _known_string(path.get("key_address"))
    vault_address = _known_string(path.get("key_vault_address"))
    grant_source_address = _known_string(path.get("grant_source_address"))
    if (
        identity_address is None
        or principal_id is None
        or key_address is None
        or vault_address is None
        or grant_source_address is None
    ):
        return False

    identity = context.inventory.get_by_address(identity_address)
    key = context.inventory.get_by_address(key_address)
    vault = context.inventory.get_by_address(vault_address)
    grant_source = context.inventory.get_by_address(grant_source_address)
    if (
        identity is None
        or key is None
        or vault is None
        or grant_source is None
        or key.resource_type != AzureResourceType.KEY_VAULT_KEY
        or vault.resource_type != AzureResourceType.KEY_VAULT
    ):
        return False

    app_facts = azure_facts(app)
    identity_facts = azure_facts(identity)
    key_facts = azure_facts(key)
    vault_facts = azure_facts(vault)
    identity_principal_id = _known_string(identity_facts.principal_id)
    path_vault_id = _known_string(path.get("key_vault_id"))
    vault_id = _known_string(vault_facts.key_vault_id)
    if (
        identity_principal_id is None
        or not _same_identifier(identity_principal_id, principal_id)
        or key_facts.key_vault_key_identity_state != "resolved"
        or key_facts.resolved_key_vault_address != vault.address
        or not _same_identifier(path_vault_id, vault_id)
        or not _has_exact_versionless_key_identity(key_facts)
        or not _path_matches_key_identity(path, key_facts)
        or not _key_operation_is_supported(key_facts, expected_key_operation)
    ):
        return False

    if path.get("identity_kind") == "system_assigned":
        if identity.address != app.address or not app_facts.has_system_assigned_identity:
            return False
    elif (
        identity.resource_type != AzureResourceType.USER_ASSIGNED_IDENTITY
        or not app_facts.has_user_assigned_identity
        or not _user_identity_is_attached(app_facts, identity.address)
    ):
        return False

    if not _grant_source_is_valid(path, grant_source, vault):
        return False
    if not _scope_is_exact(path, key, vault):
        return False

    role_definition_address = _known_string(path.get("role_definition_address"))
    if role_definition_address is not None:
        role_definition = context.inventory.get_by_address(role_definition_address)
        if role_definition is None or role_definition.resource_type != AzureResourceType.ROLE_DEFINITION:
            return False
    return True


def _user_identity_is_attached(facts: Any, address: str) -> bool:
    if address in facts.resolved_attached_identity_addresses:
        return True
    return any(
        reference == address or reference.startswith(f"{address}.") for reference in facts.attached_identity_references
    )


def _path_matches_key_identity(path: Mapping[str, Any], facts: Any) -> bool:
    return all(
        _same_optional_identifier(path.get(path_field), getattr(facts, fact_name))
        for path_field, fact_name in (
            ("key_uri", "key_vault_key_uri"),
            ("key_versionless_uri", "key_vault_key_versionless_uri"),
            ("key_resource_id", "key_vault_key_resource_id"),
            ("key_versionless_resource_id", "key_vault_key_versionless_resource_id"),
            ("key_version", "key_vault_key_version"),
        )
    )


def _same_optional_identifier(left: object, right: object) -> bool:
    left_value = _known_string(left)
    right_value = _known_string(right)
    if left_value is None or right_value is None:
        return left_value is None and right_value is None
    return left_value.casefold() == right_value.casefold()


def _same_identifier(left: str | None, right: str | None) -> bool:
    return _same_optional_identifier(left, right) and left is not None and right is not None


def _has_exact_versionless_key_identity(facts: Any) -> bool:
    return bool(
        _known_string(facts.key_vault_key_versionless_uri) or _known_string(facts.key_vault_key_versionless_resource_id)
    )


def _key_operation_is_supported(facts: Any, operation: str) -> bool:
    return operation.casefold() in {value.casefold() for value in facts.key_vault_key_ops}


def _grant_source_is_valid(
    path: Mapping[str, Any],
    source: NormalizedResource,
    vault: NormalizedResource,
) -> bool:
    grant_kind = path.get("grant_kind")
    if path.get("grant_source_type") != source.resource_type:
        return False
    if grant_kind == "access_policy":
        return (
            source.resource_type in _ACCESS_POLICY_SOURCE_TYPES
            and path.get("authorization_model") == "access_policy"
            and path.get("management_state") == "unambiguous"
            and path.get("scope_type") == "vault"
        )
    return (
        grant_kind == "rbac"
        and source.resource_type == AzureResourceType.ROLE_ASSIGNMENT
        and path.get("authorization_model") == "azure_rbac"
        and path.get("key_vault_address") == vault.address
    )


def _scope_is_exact(
    path: Mapping[str, Any],
    key: NormalizedResource,
    vault: NormalizedResource,
) -> bool:
    scope_type = path.get("scope_type")
    scope_arm_id = _known_string(path.get("scope_arm_id"))
    if scope_arm_id is None:
        return False

    key_facts = azure_facts(key)
    vault_id = _known_string(azure_facts(vault).key_vault_id)
    if scope_type == "key":
        expected = _known_string(key_facts.key_vault_key_versionless_resource_id)
    elif scope_type == "vault":
        expected = vault_id
    else:
        match = _VAULT_ID_PATTERN.fullmatch(vault_id.rstrip("/")) if vault_id is not None else None
        if match is None:
            expected = None
        elif scope_type == "subscription":
            expected = match.group("subscription")
        elif scope_type == "resource_group":
            expected = f"{match.group('subscription')}{match.group('resource_group')}"
        else:
            expected = None
    return expected is not None and expected.casefold() == scope_arm_id.casefold()


def _rationale(
    app: NormalizedResource,
    operation_class: str,
    operations: Sequence[str],
    key_addresses: list[str],
    *,
    parent_scope: bool,
) -> str:
    operation_text = _operation_text(operations)
    if operation_class == _DECRYPT_OPERATION:
        authority_text = operation_text
        capability = _plaintext_recovery_capability(operations)
    else:
        authority_text = "signing"
        capability = "could generate Key Vault signatures, creating spoofing potential"
    if parent_scope:
        scope_text = (
            "At least one modeled grant is subscription-, resource-group-, or vault-scoped, so its potential "
            "blast radius is broader than an exact-key grant. The modeled key count is not an inventory of every "
            "out-of-plan key covered by that parent scope."
        )
    else:
        scope_text = "The modeled grants are limited to exact versionless Key Vault key scope."
    qualification = (
        "This establishes cryptographic-operation authority, not proof that the workload possesses useful "
        "ciphertext, can recover application plaintext, or can produce a signature accepted by a relying "
        "application."
    )
    return (
        f"{app.display_name} has public network access enabled and its runtime managed identity has deterministic "
        f"Key Vault {authority_text} authority "
        f"on {len(key_addresses)} exact modeled key(s). A compromise of the "
        f"public workload {capability}. {scope_text} {qualification}"
    )


def _authorization_scope(
    operation_class: str,
    operations: Sequence[str],
    parent_scope: bool,
) -> list[str]:
    operation_text = _operation_text(operations) if operation_class == _DECRYPT_OPERATION else "signing"
    values = [
        f"establishes=deterministic Key Vault {operation_text} authority for the App Service runtime identity",
        "key_scope=versionless_key_authorization; key_versions_are_evidence_not_iam_scope",
        (
            "does_not_establish=useful ciphertext, plaintext recovery, accepted application signatures, key "
            "material possession, or runtime success outside modeled authorization evidence"
        ),
    ]
    if parent_scope:
        values.append(
            "blast_radius=parent-scope grant is broader than exact-key scope; out_of_plan_keys_are_not_modeled"
        )
    return values


def _path_operations(paths: Sequence[Mapping[str, Any]]) -> list[str]:
    return [
        operation
        for operation in ("decrypt", "unwrap", "sign")
        if any(path.get("operation") == operation for path in paths)
    ]


def _operation_text(operations: Sequence[str]) -> str:
    if len(operations) == 1:
        return operations[0]
    if len(operations) == 2:
        return f"{operations[0]} and {operations[1]}"
    return ", ".join(operations[:-1]) + f", and {operations[-1]}"


def _plaintext_recovery_capability(operations: Sequence[str]) -> str:
    operation_text = _operation_text(operations)
    if operations == ["decrypt"]:
        return "could submit ciphertext to Key Vault decrypt operations, creating plaintext-recovery and information-disclosure potential"
    if operations == ["unwrap"]:
        return "could submit wrapped key material to Key Vault unwrap operations, creating plaintext-recovery and information-disclosure potential"
    return (
        f"could submit ciphertext or wrapped key material to Key Vault {operation_text} operations, creating "
        "plaintext-recovery and information-disclosure potential"
    )


def _public_endpoint_evidence(app: NormalizedResource) -> list[str]:
    facts = azure_facts(app)
    return [
        f"address={app.address}",
        f"type={app.resource_type}",
        "public_network_access_enabled=true",
        f"public_network_fallback_state={facts.public_network_fallback_state}",
        f"ip_restriction_default_action={facts.app_service_ip_restriction_default_action or 'not_configured'}",
        f"ip_restriction_count={len(facts.app_service_access_restrictions)}",
    ]


def _runtime_identity_evidence(paths: Sequence[Mapping[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"identity_address={path.get('identity_address')}",
                    f"identity_kind={path.get('identity_kind')}",
                    f"principal_id={path.get('principal_id')}",
                    "credential_context=workload_runtime",
                )
            )
            for path in paths
        }
    )


def _operation_path_evidence(paths: Sequence[Mapping[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"key_address={path.get('key_address')}",
                    f"key_vault_address={path.get('key_vault_address')}",
                    f"key_name={path.get('key_name') or 'unknown'}",
                    f"key_type={path.get('key_type') or 'unknown'}",
                    f"key_uri={path.get('key_uri') or 'none'}",
                    f"key_versionless_uri={path.get('key_versionless_uri') or 'none'}",
                    f"key_resource_id={path.get('key_resource_id') or 'none'}",
                    f"key_versionless_resource_id={path.get('key_versionless_resource_id') or 'none'}",
                    f"key_version={path.get('key_version') or 'none'}",
                    f"key_operations={','.join(_string_values(path.get('key_operations')))}",
                    f"operation={path.get('operation')}",
                    f"operation_class={path.get('operation_class')}",
                    f"matched_key_operation={path.get('matched_key_operation')}",
                    f"grant_kind={path.get('grant_kind')}",
                    f"grant_source={path.get('grant_source_address')}",
                    f"grant_source_type={path.get('grant_source_type')}",
                    f"scope_type={path.get('scope_type')}",
                    f"scope={path.get('scope')}",
                    f"scope_arm_id={path.get('scope_arm_id')}",
                    f"authorization_model={path.get('authorization_model')}",
                    f"authorization_state={path.get('authorization_state')}",
                    f"authorization_model_state={path.get('authorization_model_state')}",
                    f"management_state={path.get('management_state')}",
                    f"role={path.get('role_definition_name') or path.get('role_definition_id') or 'none'}",
                    f"role_definition_address={path.get('role_definition_address') or 'none'}",
                    f"matched_data_actions={','.join(_string_values(path.get('matched_data_actions')) or ['none'])}",
                    f"key_permissions={','.join(_string_values(path.get('key_permissions')) or ['none'])}",
                    f"condition_state={path.get('condition_state')}",
                    f"condition_applicability_state={path.get('condition_applicability_state') or 'not_applicable'}",
                    f"evaluation_basis={path.get('evaluation_basis')}",
                )
            )
            for path in paths
        }
    )


def _scope_breadth_evidence(paths: Sequence[Mapping[str, Any]]) -> list[str]:
    grants_by_scope: dict[str, set[tuple[object, ...]]] = {
        scope_type: set() for scope_type in ("subscription", "resource_group", "vault", "key")
    }
    modeled_keys = {value for path in paths if isinstance(value := path.get("key_address"), str) and value}
    for path in paths:
        scope_type = path.get("scope_type")
        if scope_type not in grants_by_scope:
            continue
        grants_by_scope[scope_type].add(
            (
                path.get("grant_source_address"),
                path.get("grant_kind"),
                path.get("grant_basis"),
                path.get("scope"),
                path.get("role_definition_id") or path.get("role_definition_name"),
            )
        )
    parent_grants = sum(len(grants_by_scope[value]) for value in _PARENT_SCOPE_TYPES)
    broadest_scope = next(
        (value for value in ("subscription", "resource_group", "vault", "key") if grants_by_scope[value]),
        "unknown",
    )
    return [
        (
            f"subscription_grants={len(grants_by_scope['subscription'])}; "
            f"resource_group_grants={len(grants_by_scope['resource_group'])}; "
            f"vault_grants={len(grants_by_scope['vault'])}; "
            f"exact_key_grants={len(grants_by_scope['key'])}; "
            f"parent_scope_grants={parent_grants}; "
            f"modeled_keys={len(modeled_keys)}; "
            f"broadest_scope={broadest_scope}; "
            f"out_of_plan_keys_not_modeled=true; "
            f"blast_radius_basis={'parent_scope_grant' if parent_grants else 'exact_key_grant'}"
        )
    ]


def _path_values(paths: Sequence[Mapping[str, Any]], key: str) -> list[str]:
    return sorted({value for path in paths if isinstance(value := path.get(key), str) and value})


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _string_values(value: object) -> list[str]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]
