from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Literal, TypedDict, cast

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, EvidenceItem, Finding, NormalizedResource
from tfstride.providers.gcp.constants import PUBLIC_GCP_IAM_MEMBERS
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import (
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GCP_SECRET_MANAGER_SECRET_IAM_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import binding_members
from tfstride.providers.gcp.secret_management_evidence import (
    GcpCloudRunSecretManagementPath,
    GcpSecretManagerManagementEffect,
    GcpSecretManagerPermission,
    GcpSecretManagerVersionEvidence,
)

_SECRET_PATH_PATTERN = re.compile(r"^projects/(?P<project>[^/]+)/secrets/(?P<secret>[^/]+)$")
_VERSION_PATH_PATTERN = re.compile(
    r"^projects/(?P<project>[^/]+)/secrets/(?P<secret>[^/]+)/versions/(?P<version>[^/]+)$"
)
_PUBLIC_INVOKER_ROLES = frozenset({"roles/run.invoker", "roles/run.servicesInvoker"})
_MANAGEMENT_DEFINITIONS: dict[
    GcpSecretManagerPermission,
    tuple[str, GcpSecretManagerManagementEffect, str],
] = {
    "secretmanager.versions.add": ("value_mutation", "tampering", "secret"),
    "secretmanager.versions.disable": ("version_disruption", "disruption", "secret_version"),
    "secretmanager.versions.destroy": ("version_disruption", "disruption", "secret_version"),
    "secretmanager.secrets.delete": ("destructive_administration", "disruption", "secret"),
}
_OPERATION_ORDER: tuple[GcpSecretManagerPermission, ...] = tuple(_MANAGEMENT_DEFINITIONS)


class _PublicInvokerBinding(TypedDict):
    source: str
    role: str
    member: str


class GcpCloudRunSecretManagementRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_cloud_run_secret_tampering(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_public_management_access(context, rule_id, "tampering")

    def detect_public_cloud_run_secret_disruption(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_public_management_access(context, rule_id, "disruption")

    def _detect_public_management_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
        management_effect: GcpSecretManagerManagementEffect,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for workload in context.inventory.by_type(*GCP_CLOUD_RUN_RESOURCE_TYPES):
            public_invokers = _unconditional_public_invokers(workload)
            invoker_iam_check_disabled = gcp_facts(workload).cloud_run_invoker_iam_disabled is True
            if not workload.public_exposure or (not public_invokers and not invoker_iam_check_disabled):
                continue

            paths = [
                path
                for path in gcp_facts(workload).cloud_run_secret_management_paths
                if path.get("management_effect") == management_effect
                and _is_deterministic_management_path(path, workload, context)
            ]
            if not paths:
                continue

            secret_addresses = _path_addresses(paths, "secret_address")
            target_addresses = _target_addresses(paths)
            iam_resource_addresses = _path_addresses(paths, "iam_resource_address")
            public_source_addresses = sorted({binding["source"] for binding in public_invokers})
            operations = _operations(paths)
            project_scope = any(path.get("scope_type") == "project" for path in paths)
            secret_scope = any(path.get("scope_type") == "secret" for path in paths)
            version_destroy_paths = [
                path for path in paths if path.get("operation") == "secretmanager.versions.destroy"
            ]
            uncertainties = _relevant_uncertainties(workload, secret_addresses, target_addresses)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=(2 if "secretmanager.secrets.delete" in operations else 1),
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=(2 if project_scope or len(secret_addresses) > 1 else 1),
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
                            *secret_addresses,
                            *target_addresses,
                            *iam_resource_addresses,
                        ]
                    ),
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=_rationale(
                        workload,
                        operations,
                        secret_addresses,
                        management_effect,
                        project_scope=project_scope,
                        secret_scope=secret_scope,
                    ),
                    evidence=collect_evidence(
                        evidence_item("public_invoker_bindings", _public_invoker_evidence(public_invokers)),
                        evidence_item("public_exposure_reasons", workload.public_exposure_reasons),
                        evidence_item(
                            "public_exposure_configuration",
                            _public_exposure_configuration(workload),
                        ),
                        evidence_item("runtime_identity", _runtime_identity_evidence(paths)),
                        evidence_item("secret_management_paths", _management_path_evidence(paths)),
                        evidence_item(
                            "scope_breadth",
                            _scope_breadth_evidence(
                                paths,
                                secret_addresses,
                                target_addresses,
                            ),
                        ),
                        evidence_item(
                            "authorization_scope",
                            _authorization_scope(
                                operations,
                                management_effect,
                                project_scope=project_scope,
                                secret_scope=secret_scope,
                            ),
                        ),
                        _recovery_evidence(version_destroy_paths),
                        evidence_item("secret_management_path_uncertainties", uncertainties),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _is_deterministic_management_path(
    path: GcpCloudRunSecretManagementPath,
    workload: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    operation = path.get("operation")
    if operation not in _MANAGEMENT_DEFINITIONS:
        return False
    definition = _MANAGEMENT_DEFINITIONS[operation]
    operation_class, management_effect, target_type = definition
    if (
        path not in gcp_facts(workload).cloud_run_secret_management_paths
        or path.get("workload_address") != workload.address
        or path.get("workload_type") != workload.resource_type
        or path.get("identity_kind") != "cloud_run_service_account"
        or path.get("credential_context") != "workload_runtime"
        or path.get("operation_class") != operation_class
        or path.get("management_effect") != management_effect
        or path.get("target_type") != target_type
        or path.get("authorization_model") != "secret_manager_iam"
        or path.get("authorization_state") != "granted"
        or path.get("management_state") != "unambiguous"
        or path.get("condition_state") != "not_configured"
        or path.get("condition") is not None
        or path.get("iam_scope_is_secret_version") is not False
        or path.get("lifecycle_compatibility_state") not in {"compatible", "not_applicable"}
    ):
        return False

    workload_facts = gcp_facts(workload)
    email = _known_string(path.get("service_account_email"))
    member = _known_string(path.get("service_account_member"))
    if (
        email is None
        or member is None
        or workload_facts.service_account_email != email
        or workload_facts.service_account_member != member
        or member != f"serviceAccount:{email}"
    ):
        return False

    secret_address = _known_string(path.get("secret_address"))
    secret_resource_name = _known_string(path.get("secret_resource_name"))
    if secret_address is None or secret_resource_name is None:
        return False
    secret = context.inventory.get_by_address(secret_address)
    if (
        secret is None
        or secret.resource_type != GcpResourceType.SECRET_MANAGER_SECRET
        or _secret_resource_name(secret) != secret_resource_name
        or _project_from_secret_name(secret_resource_name) != _known_string(path.get("secret_project"))
        or path.get("version_destroy_ttl") != gcp_facts(secret).secret_manager_version_destroy_ttl
        or path.get("recovery_evidence_scope") != "secret_version_destruction_delay"
    ):
        return False

    if not _target_is_current(path, secret, secret_resource_name, target_type, context):
        return False
    return _grant_is_current(path, secret, secret_resource_name, context)


def _target_is_current(
    path: GcpCloudRunSecretManagementPath,
    secret: NormalizedResource,
    secret_resource_name: str,
    target_type: str,
    context: RuleEvaluationContext,
) -> bool:
    target_address = _known_string(path.get("target_address"))
    target_resource_name = _known_string(path.get("target_resource_name"))
    evidence_addresses = _string_values(path.get("target_model_evidence_addresses"))
    if target_address is None or target_resource_name is None or evidence_addresses != [target_address]:
        return False

    target = context.inventory.get_by_address(target_address)
    if target_type == "secret":
        return bool(
            target is not None
            and target is secret
            and path.get("target_resource_type") == target.resource_type
            and target_resource_name == secret_resource_name
            and path.get("secret_version") is None
            and path.get("lifecycle_compatibility_state") == "not_applicable"
        )
    if target_type != "secret_version" or target is None:
        return False
    if target.resource_type != GcpResourceType.SECRET_MANAGER_SECRET_VERSION:
        return False

    version_facts = gcp_facts(target)
    version_resource_name = _version_resource_name(target)
    version_evidence = _current_version_evidence(target, secret, secret_resource_name)
    if (
        version_resource_name is None
        or version_evidence is None
        or version_facts.secret_manager_version_resolved_secret_address != secret.address
        or path.get("target_resource_type") != target.resource_type
        or target_resource_name != version_resource_name
        or _parent_secret_name(version_resource_name) != secret_resource_name
        or path.get("secret_version") != version_evidence
        or path.get("lifecycle_compatibility_state") != "compatible"
        or path.get("version_destroy_ttl") != gcp_facts(secret).secret_manager_version_destroy_ttl
    ):
        return False

    operation = path.get("operation")
    lifecycle_state = version_facts.secret_manager_version_lifecycle_state
    return (operation == "secretmanager.versions.disable" and lifecycle_state == "enabled") or (
        operation == "secretmanager.versions.destroy" and lifecycle_state in {"enabled", "disabled"}
    )


def _grant_is_current(
    path: GcpCloudRunSecretManagementPath,
    secret: NormalizedResource,
    secret_resource_name: str,
    context: RuleEvaluationContext,
) -> bool:
    iam_address = _known_string(path.get("iam_resource_address"))
    iam_type = _known_string(path.get("iam_resource_type"))
    role = _known_string(path.get("role"))
    scope_type = _known_string(path.get("scope_type"))
    scope = _known_string(path.get("scope"))
    grant_record = path.get("iam_grant_record")
    if (
        iam_address is None
        or iam_type is None
        or role is None
        or scope_type not in {"project", "secret"}
        or scope is None
        or not isinstance(grant_record, Mapping)
    ):
        return False

    iam_resource = context.inventory.get_by_address(iam_address)
    grants = gcp_facts(secret).secret_manager_iam_grants
    if (
        iam_resource is None
        or iam_resource.resource_type != iam_type
        or grant_record not in grants
        or grant_record.get("source") != iam_address
        or grant_record.get("source_type") != iam_type
        or grant_record.get("role") != role
        or grant_record.get("scope_type") != scope_type
        or grant_record.get("scope") != scope
        or grant_record.get("secret_address") != secret.address
        or grant_record.get("secret_resource_name") != secret_resource_name
        or grant_record.get("project") != _project_from_secret_name(secret_resource_name)
        or path.get("iam_grant_record") != grant_record
        or path.get("grant_members") != grant_record.get("members")
        or path.get("grant_basis") != grant_record.get("grant_basis")
        or path.get("source_scope_reference") != grant_record.get("source_scope_reference")
        or path.get("management_mode") != grant_record.get("management_mode")
        or path.get("management_state") != grant_record.get("management_state")
        or path.get("condition_state") != grant_record.get("condition_state")
        or path.get("condition") != grant_record.get("condition")
        or path.get("role_kind") != grant_record.get("role_kind")
        or path.get("role_resolution_state") != grant_record.get("role_resolution_state")
        or path.get("modeled_secret_permissions") != grant_record.get("modeled_secret_permissions")
        or path.get("scope_effective_permissions") != grant_record.get("scope_effective_permissions")
        or path.get("custom_role_permissions") != grant_record.get("custom_role_permissions", [])
        or path.get("role_definition_address") != grant_record.get("role_definition_address")
        or path.get("authorization_state") != grant_record.get("authorization_state")
    ):
        return False

    if scope_type == "project":
        valid_scope = (
            iam_type in GCP_PROJECT_IAM_RESOURCE_TYPES
            and scope == _project_from_secret_name(secret_resource_name)
            and path.get("grant_basis") == "project_iam"
        )
    else:
        valid_scope = (
            iam_type in GCP_SECRET_MANAGER_SECRET_IAM_RESOURCE_TYPES
            and scope == secret_resource_name
            and path.get("grant_basis") == "secret_resource_iam"
        )
    operation = _known_string(path.get("operation"))
    matched_permissions = _string_values(path.get("matched_permissions"))
    member = _known_string(path.get("service_account_member"))
    grant_members = _string_values(path.get("grant_members"))
    return bool(
        valid_scope
        and operation is not None
        and matched_permissions == [operation]
        and operation in _string_values(path.get("scope_effective_permissions"))
        and member is not None
        and member in grant_members
    )


def _current_version_evidence(
    version: NormalizedResource,
    secret: NormalizedResource,
    secret_resource_name: str,
) -> GcpSecretManagerVersionEvidence | None:
    facts = gcp_facts(version)
    version_resource_name = _version_resource_name(version)
    version_number = facts.secret_manager_version_number
    lifecycle_state = facts.secret_manager_version_lifecycle_state
    if (
        version_resource_name is None
        or version_number is None
        or lifecycle_state is None
        or facts.secret_manager_version_resolved_secret_address != secret.address
        or _parent_secret_name(version_resource_name) != secret_resource_name
    ):
        return None
    return {
        "version_address": version.address,
        "version_resource_type": version.resource_type,
        "version_resource_name": version_resource_name,
        "version_number": version_number,
        "version_state": lifecycle_state,
        "secret_address": secret.address,
        "secret_resource_name": secret_resource_name,
        "resolved_secret_address": secret.address,
        "lifecycle_state": lifecycle_state,
        "deletion_policy": facts.secret_manager_version_deletion_policy,
        "posture_uncertainties": list(facts.secret_manager_version_posture_uncertainties),
    }


def _path_addresses(
    paths: Sequence[GcpCloudRunSecretManagementPath],
    field: Literal["secret_address", "iam_resource_address"],
) -> list[str]:
    return sorted({value for path in paths if (value := _known_string(path.get(field))) is not None})


def _target_addresses(paths: Sequence[GcpCloudRunSecretManagementPath]) -> list[str]:
    return sorted({value for path in paths if (value := _known_string(path.get("target_address"))) is not None})


def _operations(paths: Sequence[GcpCloudRunSecretManagementPath]) -> list[GcpSecretManagerPermission]:
    return [operation for operation in _OPERATION_ORDER if any(path.get("operation") == operation for path in paths)]


def _scope_breadth_evidence(
    paths: Sequence[GcpCloudRunSecretManagementPath],
    secret_addresses: Sequence[str],
    target_addresses: Sequence[str],
) -> list[str]:
    grants_by_scope: dict[str, set[tuple[str, str, str]]] = {
        scope_type: {
            (
                _known_string(path.get("iam_resource_address")) or "unknown",
                _known_string(path.get("role")) or "unknown",
                _known_string(path.get("scope")) or "unknown",
            )
            for path in paths
            if path.get("scope_type") == scope_type
        }
        for scope_type in ("project", "secret")
    }
    modeled_versions = len({path["target_address"] for path in paths if path.get("target_type") == "secret_version"})
    return [
        (
            f"project_grants={len(grants_by_scope['project'])}; "
            f"secret_grants={len(grants_by_scope['secret'])}; "
            f"modeled_secrets={len(secret_addresses)}; "
            f"modeled_versions={modeled_versions}; "
            f"target_paths={len(paths)}; "
            f"modeled_targets={len(target_addresses)}; "
            f"blast_radius_basis={'project_applicable_grant' if grants_by_scope['project'] else 'secret_scoped_grants'}"
        )
    ]


def _rationale(
    workload: NormalizedResource,
    operations: Sequence[GcpSecretManagerPermission],
    secret_addresses: Sequence[str],
    management_effect: GcpSecretManagerManagementEffect,
    *,
    project_scope: bool,
    secret_scope: bool,
) -> str:
    operation_text = _operation_text(operations)
    if management_effect == "tampering":
        capability = "could add new Secret Manager secret versions, creating tampering potential"
    else:
        capability = (
            "could disable or destroy secret versions or delete Secret Manager secrets, creating disruption potential"
        )
    if project_scope:
        scope_text = (
            "At least one grant is project-applicable and can reach modeled secrets across the project, "
            "so its blast radius is broader than a secret-scoped grant."
        )
    elif secret_scope:
        scope_text = "The modeled grants are limited to exact Secret Manager secret scope."
    else:
        scope_text = "The modeled grant scope is unresolved."
    return (
        f"{workload.display_name} is publicly invokable and its Cloud Run runtime service account has "
        f"deterministic Secret Manager {operation_text} authority on {len(secret_addresses)} exact modeled "
        f"secret(s). A compromise of the public workload {capability}. {scope_text} This establishes "
        "management authority, not proof of successful operation completion, possession of secret payloads, "
        "or impact outside the modeled IAM and lifecycle evidence."
    )


def _operation_text(operations: Sequence[GcpSecretManagerPermission]) -> str:
    labels = {
        "secretmanager.versions.add": "secret-version addition",
        "secretmanager.versions.disable": "secret-version disablement",
        "secretmanager.versions.destroy": "secret-version destruction",
        "secretmanager.secrets.delete": "secret deletion",
    }
    values = [labels[operation] for operation in operations]
    if len(values) == 1:
        return values[0]
    return ", ".join(values[:-1]) + f", and {values[-1]}"


def _authorization_scope(
    operations: Sequence[GcpSecretManagerPermission],
    management_effect: GcpSecretManagerManagementEffect,
    *,
    project_scope: bool,
    secret_scope: bool,
) -> list[str]:
    effect_text = "secret tampering" if management_effect == "tampering" else "secret disruption"
    values = [
        (
            f"establishes=deterministic {','.join(operations)} authority with {effect_text} effect "
            "for the Cloud Run runtime service account"
        ),
        "iam_scopes=project,secret; iam_scope_is_secret_version=false",
        "does_not_establish=secret payload possession, operation success, or runtime impact outside modeled IAM and lifecycle evidence",
    ]
    if project_scope:
        values.append("blast_radius=project-applicable grants are broader than exact secret grants")
    elif secret_scope:
        values.append("blast_radius=grants are limited to exact Secret Manager secret scope")
    return values


def _management_path_evidence(paths: Sequence[GcpCloudRunSecretManagementPath]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"operation={path['operation']}",
                    f"operation_class={path['operation_class']}",
                    f"management_effect={path['management_effect']}",
                    f"target_type={path['target_type']}",
                    f"target_address={path['target_address']}",
                    f"target_resource_name={path['target_resource_name']}",
                    f"secret_address={path['secret_address']}",
                    f"secret_resource_name={path['secret_resource_name']}",
                    f"secret_project={path['secret_project']}",
                    f"iam_resource={path['iam_resource_address']}",
                    f"iam_resource_type={path['iam_resource_type']}",
                    f"role={path['role']}",
                    f"role_kind={path['role_kind']}",
                    f"role_resolution_state={path['role_resolution_state']}",
                    f"matched_permissions={','.join(path['matched_permissions'])}",
                    f"scope_effective_permissions={','.join(path['scope_effective_permissions'])}",
                    f"grant_members={','.join(path['grant_members'])}",
                    f"grant_basis={path['grant_basis']}",
                    f"scope_type={path['scope_type']}",
                    f"scope={path['scope']}",
                    f"management_mode={path['management_mode']}",
                    f"management_state={path['management_state']}",
                    f"condition_state={path['condition_state']}",
                    f"authorization_state={path['authorization_state']}",
                    f"lifecycle_compatibility={path['lifecycle_compatibility_state']}",
                    f"version_destroy_ttl={path.get('version_destroy_ttl') or 'unknown'}",
                    f"version={_version_evidence(path.get('secret_version')) or 'none'}",
                )
            )
            for path in paths
        }
    )


def _version_evidence(value: object) -> str:
    if not isinstance(value, Mapping):
        return ""
    record = cast(Mapping[str, object], value)
    return ";".join(
        (
            f"address={record.get('version_address') or 'unknown'}",
            f"name={record.get('version_resource_name') or 'unknown'}",
            f"number={record.get('version_number') or 'unknown'}",
            f"state={record.get('lifecycle_state') or 'unknown'}",
            f"deletion_policy={record.get('deletion_policy') or 'unknown'}",
        )
    )


def _recovery_evidence(
    paths: Sequence[GcpCloudRunSecretManagementPath],
) -> EvidenceItem | None:
    values: list[str] = []
    for path in paths:
        ttl = _known_string(path.get("version_destroy_ttl"))
        values.append(
            "; ".join(
                (
                    f"secret_address={path['secret_address']}",
                    f"version_address={path['target_address']}",
                    "operation=secretmanager.versions.destroy",
                    f"version_destroy_ttl={ttl or 'unknown'}",
                    f"recovery_state={'version_destroy_delay' if ttl else 'unknown'}",
                    f"terraform_deletion_policy={_version_deletion_policy(path.get('secret_version'))}",
                    "runtime_secret_deletion_recovery_not_established=true",
                )
            )
        )
    return evidence_item("recovery_evidence", sorted(set(values)))


def _version_deletion_policy(value: object) -> str:
    if not isinstance(value, Mapping):
        return "unknown"
    record = cast(Mapping[str, object], value)
    policy = record.get("deletion_policy")
    return policy if isinstance(policy, str) and policy else "unknown"


def _runtime_identity_evidence(paths: Sequence[GcpCloudRunSecretManagementPath]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"service_account={path['service_account_email']}",
                    f"member={path['service_account_member']}",
                    "identity_kind=cloud_run_service_account",
                    "credential_context=workload_runtime",
                )
            )
            for path in paths
        }
    )


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


def _public_invoker_evidence(invokers: Sequence[_PublicInvokerBinding]) -> list[str]:
    return sorted(
        {
            f"source={invoker['source']}; role={invoker['role']}; member={invoker['member']}; condition=none"
            for invoker in invokers
        }
    )


def _public_exposure_configuration(resource: NormalizedResource) -> list[str]:
    if gcp_facts(resource).cloud_run_invoker_iam_disabled is not True:
        return []
    return [f"invoker_iam_check=disabled; ingress={gcp_facts(resource).serverless_ingress or 'unknown'}"]


def _relevant_uncertainties(
    workload: NormalizedResource,
    secret_addresses: Sequence[str],
    target_addresses: Sequence[str],
) -> list[str]:
    markers = (*secret_addresses, *target_addresses)
    return sorted(
        {
            uncertainty
            for uncertainty in gcp_facts(workload).cloud_run_secret_management_path_uncertainties
            if any(marker in uncertainty for marker in markers)
        }
    )


def _secret_resource_name(secret: NormalizedResource) -> str | None:
    facts = gcp_facts(secret)
    for value in (facts.resource_name, secret.identifier):
        if isinstance(value, str) and _SECRET_PATH_PATTERN.fullmatch(value):
            return value
    project = _known_string(facts.project)
    secret_id = _known_string(facts.secret_id)
    if project is not None and secret_id is not None and "/" not in secret_id:
        return f"projects/{project}/secrets/{secret_id}"
    return None


def _version_resource_name(version: NormalizedResource) -> str | None:
    facts = gcp_facts(version)
    for value in (facts.secret_manager_version_reference, version.identifier):
        if isinstance(value, str) and _VERSION_PATH_PATTERN.fullmatch(value):
            return value
    return None


def _project_from_secret_name(value: str) -> str | None:
    match = _SECRET_PATH_PATTERN.fullmatch(value)
    return match.group("project") if match is not None else None


def _parent_secret_name(value: str) -> str | None:
    match = _VERSION_PATH_PATTERN.fullmatch(value)
    if match is None:
        return None
    return f"projects/{match.group('project')}/secrets/{match.group('secret')}"


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _string_values(value: object) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return [item for item in value if isinstance(item, str) and item]
