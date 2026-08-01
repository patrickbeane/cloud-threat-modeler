from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Literal, TypedDict

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding, NormalizedResource
from tfstride.providers.gcp.constants import PUBLIC_GCP_IAM_MEMBERS
from tfstride.providers.gcp.kms_evidence import (
    GcpCloudRunKmsOperationPath,
    GcpKmsKeyVersionEvidence,
    GcpKmsOperationClass,
    GcpKmsOperationPermission,
    GcpKmsScopeType,
)
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import (
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES,
    GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import binding_members


class _PublicInvokerBinding(TypedDict):
    source: str
    role: str
    member: str


_PathAddressKey = Literal["key_address", "iam_resource_address"]


_PUBLIC_INVOKER_ROLES = frozenset({"roles/run.invoker", "roles/run.servicesInvoker"})
_DECRYPT_OPERATION: GcpKmsOperationClass = "decrypt"
_SIGN_OPERATION: GcpKmsOperationClass = "sign"
_MAC_GENERATION_OPERATION: GcpKmsOperationClass = "mac_generation"
_SIGNING_OPERATIONS: frozenset[GcpKmsOperationClass] = frozenset({_SIGN_OPERATION, _MAC_GENERATION_OPERATION})
_OPERATION_PERMISSIONS: dict[GcpKmsOperationClass, GcpKmsOperationPermission] = {
    _DECRYPT_OPERATION: "cloudkms.cryptoKeyVersions.useToDecrypt",
    _SIGN_OPERATION: "cloudkms.cryptoKeyVersions.useToSign",
    _MAC_GENERATION_OPERATION: "cloudkms.cryptoKeyVersions.useToSign",
}
_OPERATION_PURPOSES: dict[GcpKmsOperationClass, str] = {
    _DECRYPT_OPERATION: "ENCRYPT_DECRYPT",
    _SIGN_OPERATION: "ASYMMETRIC_SIGN",
    _MAC_GENERATION_OPERATION: "MAC",
}
_KMS_KEY_PATH_PATTERN = re.compile(
    r"^projects/(?P<project>[^/]+)/locations/(?P<location>[^/]+)/"
    r"keyRings/(?P<key_ring>[^/]+)/cryptoKeys/(?P<key>[^/]+)$"
)
_PROJECT_IAM_TYPES = GCP_PROJECT_IAM_RESOURCE_TYPES
_KEY_RING_IAM_TYPES = GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES
_CRYPTO_KEY_IAM_TYPES = GCP_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES


class GcpCloudRunKmsOperationRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_cloud_run_kms_decrypt_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_public_operation_access(
            context,
            rule_id,
            frozenset({_DECRYPT_OPERATION}),
            disclosure=True,
        )

    def detect_public_cloud_run_kms_signing_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_public_operation_access(
            context,
            rule_id,
            _SIGNING_OPERATIONS,
            disclosure=False,
        )

    def _detect_public_operation_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
        operation_classes: frozenset[GcpKmsOperationClass],
        *,
        disclosure: bool,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for workload in context.inventory.by_type(*GCP_CLOUD_RUN_RESOURCE_TYPES):
            public_invokers = _unconditional_public_invokers(workload)
            invoker_iam_check_disabled = gcp_facts(workload).cloud_run_invoker_iam_disabled is True
            if not workload.public_exposure or (not public_invokers and not invoker_iam_check_disabled):
                continue

            paths: list[GcpCloudRunKmsOperationPath] = [
                path
                for path in gcp_facts(workload).cloud_run_kms_operation_paths
                if path["operation_class"] in operation_classes
                and _is_deterministic_operation_path(
                    path,
                    workload,
                    context,
                    path["operation_class"],
                )
            ]
            if not paths:
                continue

            key_addresses = _path_string_values(paths, "key_address")
            iam_resource_addresses = _path_string_values(paths, "iam_resource_address")
            public_source_addresses: list[str] = sorted({binding["source"] for binding in public_invokers})
            project_scope = any(path.get("scope_type") == "project" for path in paths)
            matched_operations = _path_operation_classes(paths)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=1,
                data_sensitivity=2 if disclosure else 1,
                lateral_movement=1,
                blast_radius=2 if project_scope else 1,
            )
            boundary = context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", workload.address))
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            workload.address,
                            *public_source_addresses,
                            *key_addresses,
                            *iam_resource_addresses,
                        ]
                    ),
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=_rationale(
                        workload,
                        matched_operations,
                        key_addresses,
                        project_scope=project_scope,
                        disclosure=disclosure,
                    ),
                    evidence=collect_evidence(
                        evidence_item("public_invoker_bindings", _public_invoker_evidence(public_invokers)),
                        evidence_item("public_exposure_reasons", workload.public_exposure_reasons),
                        evidence_item(
                            "public_exposure_configuration",
                            _public_exposure_configuration(workload),
                        ),
                        evidence_item("runtime_identity", _runtime_identity_evidence(paths)),
                        evidence_item("kms_operation_paths", _operation_path_evidence(paths)),
                        evidence_item("scope_breadth", _scope_breadth_evidence(paths)),
                        evidence_item(
                            "authorization_scope",
                            _authorization_scope(
                                matched_operations,
                                project_scope,
                            ),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _unconditional_public_invokers(
    resource: NormalizedResource,
) -> list[_PublicInvokerBinding]:
    invokers: list[_PublicInvokerBinding] = []
    for binding in gcp_facts(resource).bindings:
        role = _known_string(binding.get("role"))
        source = _known_string(binding.get("source"))
        if (
            role not in _PUBLIC_INVOKER_ROLES
            or source is None
            or binding.get("condition")
            or binding.get("condition_state") == "unknown"
        ):
            continue
        for member in binding_members(binding):
            if member in PUBLIC_GCP_IAM_MEMBERS:
                invokers.append({"source": source, "role": role, "member": member})
    return invokers


def _is_deterministic_operation_path(
    path: GcpCloudRunKmsOperationPath,
    workload: NormalizedResource,
    context: RuleEvaluationContext,
    operation_class: GcpKmsOperationClass,
) -> bool:
    if (
        path.get("workload_address") != workload.address
        or path.get("workload_type") != workload.resource_type
        or path.get("identity_kind") != "cloud_run_service_account"
        or path.get("credential_context") != "workload_runtime"
        or path.get("key_resource_type") != GcpResourceType.KMS_CRYPTO_KEY
        or path.get("authorization_model") != "cloud_kms_iam"
        or path.get("authorization_state") != "granted"
        or path.get("management_state") != "unambiguous"
        or path.get("condition_state") != "not_configured"
        or path.get("iam_scope_is_key_version") is not False
        or path.get("operation_class") != operation_class
    ):
        return False

    expected_permission = _OPERATION_PERMISSIONS[operation_class]
    expected_purpose = _OPERATION_PURPOSES[operation_class]
    if (
        path.get("operation") != expected_permission
        or path.get("matched_permissions") != [expected_permission]
        or path.get("key_purpose") != expected_purpose
    ):
        return False

    service_account_member = _known_string(path.get("service_account_member"))
    workload_member = gcp_facts(workload).service_account_member
    key_address = _known_string(path.get("key_address"))
    key_resource_name = _known_string(path.get("key_resource_name"))
    iam_resource_address = _known_string(path.get("iam_resource_address"))
    iam_resource_type = _known_string(path.get("iam_resource_type"))
    scope_type = _known_string(path.get("scope_type"))
    scope = _known_string(path.get("scope"))
    if (
        service_account_member is None
        or workload_member is None
        or key_address is None
        or key_resource_name is None
        or iam_resource_address is None
        or iam_resource_type is None
        or scope_type is None
        or scope is None
        or service_account_member != workload_member
    ):
        return False

    key = context.inventory.get_by_address(key_address)
    iam_resource = context.inventory.get_by_address(iam_resource_address)
    if (
        key is None
        or key.resource_type != GcpResourceType.KMS_CRYPTO_KEY
        or iam_resource is None
        or iam_resource.resource_type != iam_resource_type
    ):
        return False

    key_identity = _key_identity(key)
    if key_identity is None or key_identity != key_resource_name:
        return False

    key_match = _KMS_KEY_PATH_PATTERN.fullmatch(key_identity)
    if key_match is None:
        return False
    if path.get("key_project") != key_match.group("project") or path.get("key_ring") != _key_ring(key_identity):
        return False

    expected_scope_type, expected_scope = _expected_scope(
        iam_resource_type,
        key_identity,
        key_match.group("project"),
    )
    return (
        scope_type == expected_scope_type
        and scope == expected_scope
        and path.get("grant_basis") in {"project_iam", "key_ring_iam", "crypto_key_iam"}
    )


def _expected_scope(
    iam_resource_type: str,
    key_identity: str,
    project: str,
) -> tuple[GcpKmsScopeType | None, str | None]:
    if iam_resource_type in _PROJECT_IAM_TYPES:
        return "project", project
    if iam_resource_type in _KEY_RING_IAM_TYPES:
        return "key_ring", _key_ring(key_identity)
    if iam_resource_type in _CRYPTO_KEY_IAM_TYPES:
        return "crypto_key", key_identity
    return None, None


def _key_identity(resource: NormalizedResource) -> str | None:
    facts = gcp_facts(resource)
    for value in (facts.kms_crypto_key_reference, resource.identifier):
        text = _known_string(value)
        if text is not None and _KMS_KEY_PATH_PATTERN.fullmatch(text.rstrip("/")) is not None:
            return text.rstrip("/")
    return None


def _key_ring(key_identity: str) -> str:
    return key_identity.rsplit("/cryptoKeys/", 1)[0]


def _rationale(
    workload: NormalizedResource,
    operation_classes: list[GcpKmsOperationClass],
    key_addresses: list[str],
    *,
    project_scope: bool,
    disclosure: bool,
) -> str:
    operation_text = _operation_text(operation_classes)
    if disclosure:
        capability = "could attempt Cloud KMS decrypt operations, creating information-disclosure potential"
    elif operation_classes == [_SIGN_OPERATION]:
        capability = "could generate Cloud KMS signatures, creating spoofing potential"
    elif operation_classes == [_MAC_GENERATION_OPERATION]:
        capability = "could generate Cloud KMS message authentication codes, creating spoofing potential"
    else:
        capability = "could generate Cloud KMS signatures or message authentication codes, creating spoofing potential"
    scope_text = (
        "At least one grant is project-applicable and can reach modeled CryptoKeys across the project, "
        "so its blast radius is broader than a key-ring- or exact-key-scoped grant."
        if project_scope
        else "The modeled grants are limited to key-ring or exact CryptoKey scopes."
    )
    return (
        f"{workload.display_name} is publicly invokable and its Cloud Run runtime service account has "
        f"deterministic Cloud KMS {operation_text} authority on {len(key_addresses)} exact modeled CryptoKey(s). "
        f"A compromise of the public workload {capability}. {scope_text} This establishes cryptographic-operation "
        "authority, not proof that the workload possesses useful ciphertext, can disclose plaintext, or can produce "
        "a signature or message authentication code accepted by a relying application. Cloud KMS IAM is modeled at "
        "project, key-ring, and CryptoKey scope; it is not treated as CryptoKeyVersion-scoped authority."
    )


def _authorization_scope(
    operation_classes: list[GcpKmsOperationClass],
    project_scope: bool,
) -> list[str]:
    permissions = sorted({_OPERATION_PERMISSIONS[operation] for operation in operation_classes})
    values = [
        (
            f"establishes=deterministic {','.join(permissions)} IAM authority for "
            f"Cloud KMS {_operation_text(operation_classes)} operations by the Cloud Run runtime service account"
        ),
        "iam_scopes=project,key_ring,crypto_key; iam_scope_is_key_version=false",
        "excludes=cloudkms.cryptoKeyVersions.useToDecryptViaDelegation for direct Cloud Run API use",
        (
            "does_not_establish=useful ciphertext, plaintext disclosure, accepted application signatures or MACs, "
            "or runtime success outside modeled IAM evidence"
        ),
    ]
    if project_scope:
        values.append("blast_radius=project-applicable grant is broader than key-ring or exact-key grants")
    return values


def _path_operation_classes(
    paths: Sequence[GcpCloudRunKmsOperationPath],
) -> list[GcpKmsOperationClass]:
    return [
        operation
        for operation in (
            _DECRYPT_OPERATION,
            _SIGN_OPERATION,
            _MAC_GENERATION_OPERATION,
        )
        if any(path.get("operation_class") == operation for path in paths)
    ]


def _operation_text(operation_classes: Sequence[GcpKmsOperationClass]) -> str:
    labels = {
        _DECRYPT_OPERATION: "decrypt",
        _SIGN_OPERATION: "sign",
        _MAC_GENERATION_OPERATION: "MAC-generation",
    }
    operations = [labels[operation] for operation in operation_classes]
    if len(operations) == 1:
        return operations[0]
    return " and ".join(operations)


def _scope_breadth_evidence(
    paths: Sequence[GcpCloudRunKmsOperationPath],
) -> list[str]:
    grants_by_scope: dict[GcpKmsScopeType, set[tuple[str, str, str]]] = {
        scope_type: {
            (
                path["iam_resource_address"],
                path["role"],
                path["scope"],
            )
            for path in paths
            if path.get("scope_type") == scope_type
        }
        for scope_type in ("project", "key_ring", "crypto_key")
    }
    modeled_keys: set[str] = {path["key_address"] for path in paths}
    return [
        (
            f"project_grants={len(grants_by_scope['project'])}; "
            f"key_ring_grants={len(grants_by_scope['key_ring'])}; "
            f"exact_key_grants={len(grants_by_scope['crypto_key'])}; "
            f"modeled_keys={len(modeled_keys)}; "
            f"blast_radius_basis={'project_applicable_grant' if grants_by_scope['project'] else 'key_ring_or_exact_key_grant'}"
        )
    ]


def _runtime_identity_evidence(paths: Sequence[GcpCloudRunKmsOperationPath]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"service_account={path.get('service_account_email') or 'unknown'}",
                    f"member={path.get('service_account_member') or 'unknown'}",
                    "identity_kind=cloud_run_service_account",
                    "credential_context=workload_runtime",
                )
            )
            for path in paths
        }
    )


def _operation_path_evidence(paths: Sequence[GcpCloudRunKmsOperationPath]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"key_address={path['key_address']}",
                    f"key_resource_name={path['key_resource_name']}",
                    f"key_project={path['key_project']}",
                    f"key_ring={path['key_ring']}",
                    f"key_purpose={path['key_purpose']}",
                    f"operation={path['operation']}",
                    f"operation_class={path['operation_class']}",
                    f"iam_resource={path['iam_resource_address']}",
                    f"iam_resource_type={path['iam_resource_type']}",
                    f"role={path.get('role') or 'unknown'}",
                    f"scope_type={path['scope_type']}",
                    f"scope={path['scope']}",
                    f"grant_basis={path.get('grant_basis') or 'unknown'}",
                    f"authorization_state={path['authorization_state']}",
                    f"management_state={path['management_state']}",
                    f"condition_state={path['condition_state']}",
                    f"iam_scope_is_key_version={str(path['iam_scope_is_key_version']).lower()}",
                    f"key_version_evidence_scope={path.get('key_version_evidence_scope') or 'none'}",
                    f"key_versions={_version_evidence(path.get('key_versions')) or 'none'}",
                )
            )
            for path in paths
        }
    )


def _version_evidence(
    versions: Sequence[GcpKmsKeyVersionEvidence],
) -> list[str]:
    records: list[str] = []
    for version in versions:
        records.append(
            ";".join(
                (
                    "address=" + version["version_address"],
                    "name=" + (version["version_resource_name"] or "unknown"),
                    "state=" + (version["state"] or "unknown"),
                    "algorithm=" + (version["algorithm"] or "unknown"),
                    "protection_level=" + (version["protection_level"] or "unknown"),
                    "import_posture=" + (version["import_posture"] or "unknown"),
                )
            )
        )
    return sorted(records)


def _public_exposure_configuration(resource: NormalizedResource) -> list[str]:
    if gcp_facts(resource).cloud_run_invoker_iam_disabled is not True:
        return []
    ingress = gcp_facts(resource).serverless_ingress or "unknown"
    return [f"invoker_iam_check=disabled; ingress={ingress}"]


def _public_invoker_evidence(invokers: Sequence[_PublicInvokerBinding]) -> list[str]:
    return sorted(
        {
            f"source={invoker['source']}; role={invoker['role']}; member={invoker['member']}; condition=none"
            for invoker in invokers
        }
    )


def _path_string_values(
    paths: Sequence[GcpCloudRunKmsOperationPath],
    key: _PathAddressKey,
) -> list[str]:
    return sorted({path[key] for path in paths})


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None
