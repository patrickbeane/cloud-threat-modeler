from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, TypeGuard

from tfstride.models import NormalizedResource
from tfstride.providers.coercion import dedupe
from tfstride.providers.gcp.kms_evidence import (
    GcpCloudRunKmsManagementPath,
    GcpCloudRunKmsOperationPath,
    GcpKmsIamGrant,
    GcpKmsKeyVersionEvidence,
    GcpKmsManagementEffect,
    GcpKmsManagementIamGrant,
    GcpKmsManagementLifecycleCompatibility,
    GcpKmsManagementOperationClass,
    GcpKmsManagementPermission,
    GcpKmsManagementTargetType,
    GcpKmsOperationClass,
    GcpKmsOperationPermission,
    GcpKmsScopeType,
)
from tfstride.providers.gcp.resource_decoration.iam import iam_bindings
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext
from tfstride.providers.gcp.resource_types import (
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES,
    GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GcpResourceType,
)

_DECRYPT_PERMISSION: GcpKmsOperationPermission = "cloudkms.cryptoKeyVersions.useToDecrypt"
_DELEGATED_DECRYPT_PERMISSION = "cloudkms.cryptoKeyVersions.useToDecryptViaDelegation"
_SIGN_PERMISSION: GcpKmsOperationPermission = "cloudkms.cryptoKeyVersions.useToSign"
_RELEVANT_PERMISSIONS: frozenset[GcpKmsOperationPermission] = frozenset({_DECRYPT_PERMISSION, _SIGN_PERMISSION})
_VERSION_UPDATE_PERMISSION: GcpKmsManagementPermission = "cloudkms.cryptoKeyVersions.update"
_VERSION_DESTROY_PERMISSION: GcpKmsManagementPermission = "cloudkms.cryptoKeyVersions.destroy"
_KEY_SET_IAM_POLICY_PERMISSION: GcpKmsManagementPermission = "cloudkms.cryptoKeys.setIamPolicy"
_KEY_RING_SET_IAM_POLICY_PERMISSION: GcpKmsManagementPermission = "cloudkms.keyRings.setIamPolicy"
_MANAGEMENT_PATH_DEFINITIONS: dict[
    GcpKmsManagementPermission,
    tuple[
        GcpKmsManagementOperationClass,
        GcpKmsManagementEffect,
        GcpKmsManagementTargetType,
    ],
] = {
    _VERSION_UPDATE_PERMISSION: (
        "disruptive_administration",
        "disruption",
        "crypto_key_version",
    ),
    _VERSION_DESTROY_PERMISSION: (
        "destructive_administration",
        "disruption",
        "crypto_key_version",
    ),
    _KEY_SET_IAM_POLICY_PERMISSION: (
        "authorization_administration",
        "delegation",
        "crypto_key",
    ),
    _KEY_RING_SET_IAM_POLICY_PERMISSION: (
        "authorization_administration",
        "delegation",
        "key_ring",
    ),
}
_MANAGEMENT_PERMISSIONS = frozenset(_MANAGEMENT_PATH_DEFINITIONS)
_VERSION_MANAGEMENT_PERMISSIONS = frozenset({_VERSION_UPDATE_PERMISSION, _VERSION_DESTROY_PERMISSION})
_UNRESOLVED_VERSION_MANAGEMENT_MARKERS = (
    "IAM policy_data is",
    "IAM members are unresolved",
    "IAM role is unresolved",
    "IAM role or members are unresolved",
    "permissions for IAM role",
    "IAM scope is unresolved",
)
_IAM_RESOURCE_TYPES = (
    GCP_PROJECT_IAM_RESOURCE_TYPES | GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES | GCP_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES
)
_KEY_PATH_PATTERN = re.compile(
    r"^projects/(?P<project>[^/]+)/locations/(?P<location>[^/]+)/"
    r"keyRings/(?P<key_ring>[^/]+)/cryptoKeys/(?P<key>[^/]+)$"
)
_VERSION_PATH_PATTERN = re.compile(
    r"^(?P<key_path>projects/[^/]+/locations/[^/]+/keyRings/[^/]+/"
    r"cryptoKeys/[^/]+)/cryptoKeyVersions/(?P<version>[^/]+)$"
)
_KEY_RING_PATH_PATTERN = re.compile(r"^projects/[^/]+/locations/[^/]+/keyRings/[^/]+$")


@dataclass(frozen=True, slots=True)
class _KeyIdentity:
    path: str
    key_ring: str
    project: str
    purpose: str | None


@dataclass(frozen=True, slots=True)
class _ManagementTarget:
    target_type: GcpKmsManagementTargetType
    address: str | None
    resource_type: str
    resource_name: str
    model_evidence_addresses: tuple[str, ...]
    crypto_key_address: str | None
    crypto_key_resource_name: str | None
    key_version: GcpKmsKeyVersionEvidence | None
    lifecycle_compatibility_state: GcpKmsManagementLifecycleCompatibility


class ModelCloudRunKmsOperationPathsStage:
    """Project deterministic Cloud KMS operation authority onto Cloud Run."""

    name = "model_cloud_run_kms_operation_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: GcpDecorationContext,
    ) -> None:
        del context
        resources_by_address = {resource.address: resource for resource in resources}
        keys = tuple(resource for resource in resources if resource.resource_type == GcpResourceType.KMS_CRYPTO_KEY)
        versions = tuple(
            resource for resource in resources if resource.resource_type == GcpResourceType.KMS_CRYPTO_KEY_VERSION
        )
        for workload in resources:
            if workload.resource_type not in GCP_CLOUD_RUN_RESOURCE_TYPES:
                continue
            paths, uncertainties = _cloud_run_kms_operation_paths(
                workload,
                keys,
                versions,
                resources_by_address,
            )
            facts = gcp_facts(workload)
            facts.set_cloud_run_kms_operation_paths(paths)
            facts.extend_cloud_run_kms_operation_path_uncertainties(uncertainties)


class ModelCloudRunKmsManagementPathsStage:
    """Project deterministic Cloud KMS management authority onto Cloud Run."""

    name = "model_cloud_run_kms_management_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: GcpDecorationContext,
    ) -> None:
        del context
        resources_by_address = {resource.address: resource for resource in resources}
        keys = tuple(resource for resource in resources if resource.resource_type == GcpResourceType.KMS_CRYPTO_KEY)
        versions = tuple(
            resource for resource in resources if resource.resource_type == GcpResourceType.KMS_CRYPTO_KEY_VERSION
        )
        key_rings = tuple(resource for resource in resources if resource.resource_type == GcpResourceType.KMS_KEY_RING)
        ring_resources = _key_ring_resources_by_path(key_rings)
        for workload in resources:
            if workload.resource_type not in GCP_CLOUD_RUN_RESOURCE_TYPES:
                continue
            paths, uncertainties = _cloud_run_kms_management_paths(
                workload,
                keys,
                versions,
                key_rings,
                ring_resources,
                resources_by_address,
            )
            facts = gcp_facts(workload)
            facts.set_cloud_run_kms_management_paths(paths)
            facts.extend_cloud_run_kms_management_path_uncertainties(uncertainties)


def _cloud_run_kms_operation_paths(
    workload: NormalizedResource,
    keys: Sequence[NormalizedResource],
    versions: Sequence[NormalizedResource],
    resources_by_address: Mapping[str, NormalizedResource],
) -> tuple[list[GcpCloudRunKmsOperationPath], list[str]]:
    workload_facts = gcp_facts(workload)
    service_account_email = workload_facts.service_account_email
    service_account_member = workload_facts.service_account_member
    if (
        service_account_email is None
        or service_account_member is None
        or not _is_exact_service_account_identity(
            service_account_email,
            service_account_member,
        )
    ):
        return [], [f"{workload.address}: Cloud Run service account identity is unresolved"]

    paths: list[GcpCloudRunKmsOperationPath] = []
    uncertainties: list[str] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for key in keys:
        identity = _key_identity(key)
        if identity is None:
            uncertainties.append(f"{workload.address}: Cloud KMS key {key.address} has unresolved exact ancestry")
            continue

        key_facts = gcp_facts(key)
        version_records = _key_version_records(key, identity.path, versions)
        sources_with_unresolved_members: set[str] = {
            uncertainty.partition(":")[0]
            for uncertainty in key_facts.kms_iam_posture_uncertainties
            if "IAM members are unresolved" in uncertainty
        }
        sources_with_resolved_member_applicability: set[str] = set()
        sources_requiring_generic_uncertainty: set[str] = set()
        for grant in key_facts.kms_iam_grants:
            source = _known_string(grant.get("source"))
            raw_members = grant.get("members")
            members = _string_list(raw_members)
            if (
                source is not None
                and source not in sources_with_unresolved_members
                and grant.get("members_state") != "unknown"
                and isinstance(raw_members, list)
                and all(isinstance(member, str) and member for member in raw_members)
            ):
                sources_with_resolved_member_applicability.add(source)
            if service_account_member not in members:
                continue

            permissions = _string_list(grant.get("scope_effective_permissions"))
            candidate_permissions: list[GcpKmsOperationPermission] = [
                permission for permission in permissions if _is_relevant_permission(permission)
            ]
            role_resolution_state = _known_string(grant.get("role_resolution_state"))
            if not candidate_permissions:
                if source is not None and role_resolution_state not in {"resolved", "modeled_subset"}:
                    sources_requiring_generic_uncertainty.add(source)
                continue

            role = _known_string(grant.get("role"))
            if not _grant_is_exact_for_key(
                grant,
                key,
                identity,
                resources_by_address,
            ):
                uncertainties.append(
                    f"{workload.address}: {source or key.address} Cloud KMS IAM grant scope "
                    f"is unresolved for {key.address}"
                )
                continue

            for permission in candidate_permissions:
                operation_class = _operation_class(permission, identity.purpose)
                if operation_class is None:
                    if identity.purpose is None:
                        uncertainties.append(
                            f"{workload.address}: Cloud KMS key {key.address} purpose is unresolved for {permission}"
                        )
                    continue

                authorization_state = _known_string(grant.get("authorization_state"))
                management_state = _known_string(grant.get("management_state"))
                condition_state = _known_string(grant.get("condition_state"))
                if (
                    authorization_state != "granted"
                    or management_state != "unambiguous"
                    or condition_state != "not_configured"
                ):
                    uncertainties.append(
                        f"{workload.address}: {source or key.address} has non-deterministic "
                        f"{permission} authority for {service_account_member} on {key.address} "
                        f"(authorization_state={authorization_state or 'unknown'}, "
                        f"management_state={management_state or 'unknown'}, "
                        f"condition_state={condition_state or 'unknown'})"
                    )
                    continue

                fingerprint = (
                    key.address,
                    source or "",
                    role or "",
                    permission,
                    str(grant.get("scope")),
                )
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                paths.append(
                    _operation_path_record(
                        workload,
                        key,
                        identity,
                        service_account_email,
                        service_account_member,
                        permission,
                        operation_class,
                        grant,
                        version_records,
                    )
                )

        for uncertainty in key_facts.kms_iam_posture_uncertainties:
            source = uncertainty.partition(":")[0]
            if (
                source in sources_with_resolved_member_applicability
                and source not in sources_requiring_generic_uncertainty
            ):
                continue
            uncertainties.append(
                f"{workload.address}: Cloud KMS IAM posture for {key.address} is incomplete: {uncertainty}"
            )

    paths.sort(
        key=lambda path: (
            str(path["key_address"]),
            str(path["operation_class"]),
            str(path["iam_resource_address"]),
            str(path["role"]),
        )
    )
    return paths, dedupe(uncertainties)


def _cloud_run_kms_management_paths(
    workload: NormalizedResource,
    keys: Sequence[NormalizedResource],
    versions: Sequence[NormalizedResource],
    key_rings: Sequence[NormalizedResource],
    ring_resources: Mapping[str, tuple[NormalizedResource, ...]],
    resources_by_address: Mapping[str, NormalizedResource],
) -> tuple[list[GcpCloudRunKmsManagementPath], list[str]]:
    workload_facts = gcp_facts(workload)
    service_account_email = workload_facts.service_account_email
    service_account_member = workload_facts.service_account_member
    if (
        service_account_email is None
        or service_account_member is None
        or not _is_exact_service_account_identity(
            service_account_email,
            service_account_member,
        )
    ):
        return [], [f"{workload.address}: Cloud Run service account identity is unresolved for Cloud KMS management"]

    paths: list[GcpCloudRunKmsManagementPath] = []
    uncertainties: list[str] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    modeled_key_addresses = {key.address for key in keys}
    associated_version_addresses = {
        version.address
        for version in versions
        if gcp_facts(version).kms_crypto_key_version_resolved_key_address in modeled_key_addresses
    }
    for key in keys:
        identity = _key_identity(key)
        if identity is None:
            uncertainties.append(
                f"{workload.address}: Cloud KMS key {key.address} has "
                "unresolved exact ancestry for management-path projection"
            )
            continue

        key_facts = gcp_facts(key)
        version_records = _key_version_records(key, identity.path, versions)
        sources_with_unresolved_members: set[str] = {
            uncertainty.partition(":")[0]
            for uncertainty in key_facts.kms_iam_posture_uncertainties
            if "IAM members are unresolved" in uncertainty
        }
        sources_with_resolved_member_applicability: set[str] = set()
        sources_requiring_generic_uncertainty: set[str] = set()
        for grant in key_facts.kms_iam_grants:
            source = _known_string(grant.get("source"))
            raw_members = grant.get("members")
            members = _string_list(raw_members)
            if (
                source is not None
                and source not in sources_with_unresolved_members
                and grant.get("members_state") != "unknown"
                and isinstance(raw_members, list)
                and all(isinstance(member, str) and member for member in raw_members)
            ):
                sources_with_resolved_member_applicability.add(source)
            if service_account_member not in members:
                continue

            permissions = _string_list(grant.get("scope_effective_permissions"))
            candidate_permissions: list[GcpKmsManagementPermission] = [
                permission for permission in permissions if _is_management_permission(permission)
            ]
            role_resolution_state = _known_string(grant.get("role_resolution_state"))
            if not candidate_permissions:
                if source is not None and role_resolution_state not in {"resolved", "modeled_subset"}:
                    sources_requiring_generic_uncertainty.add(source)
                continue

            role = _known_string(grant.get("role"))
            if not _grant_is_exact_for_key(
                grant,
                key,
                identity,
                resources_by_address,
            ):
                uncertainties.append(
                    f"{workload.address}: {source or key.address} Cloud KMS "
                    f"IAM grant scope is unresolved for management of "
                    f"{key.address}"
                )
                continue

            for permission in candidate_permissions:
                definition = _MANAGEMENT_PATH_DEFINITIONS[permission]
                operation_class, management_effect, target_type = definition
                targets, target_uncertainties = _management_targets(
                    permission,
                    target_type,
                    key,
                    identity,
                    version_records,
                    keys,
                    ring_resources,
                    resources_by_address,
                )
                uncertainties.extend(f"{workload.address}: {uncertainty}" for uncertainty in target_uncertainties)
                if not targets:
                    continue

                authorization_state = _known_string(grant.get("authorization_state"))
                management_state = _known_string(grant.get("management_state"))
                condition_state = _known_string(grant.get("condition_state"))
                if (
                    authorization_state != "granted"
                    or management_state != "unambiguous"
                    or condition_state != "not_configured"
                ):
                    uncertainties.extend(
                        (
                            f"{workload.address}: {source or key.address} has "
                            f"non-deterministic {permission} authority for "
                            f"{service_account_member} on "
                            f"{target.resource_name} "
                            f"(authorization_state="
                            f"{authorization_state or 'unknown'}, "
                            f"management_state={management_state or 'unknown'}, "
                            f"condition_state={condition_state or 'unknown'})"
                        )
                        for target in targets
                    )
                    continue

                for target in targets:
                    fingerprint = (
                        target.resource_name,
                        source or "",
                        role or "",
                        permission,
                        str(grant.get("scope")),
                    )
                    if fingerprint in seen:
                        continue
                    seen.add(fingerprint)
                    paths.append(
                        _management_path_record(
                            workload,
                            service_account_email,
                            service_account_member,
                            permission,
                            operation_class,
                            management_effect,
                            target,
                            identity.project,
                            identity.key_ring,
                            grant,
                        )
                    )

        for uncertainty in key_facts.kms_iam_posture_uncertainties:
            source = uncertainty.partition(":")[0]
            if (
                source in sources_with_resolved_member_applicability
                and source not in sources_requiring_generic_uncertainty
            ):
                continue
            uncertainties.append(
                f"{workload.address}: Cloud KMS IAM posture for "
                f"{key.address} is incomplete for management paths: "
                f"{uncertainty}"
            )

    ring_paths, ring_uncertainties = _standalone_key_ring_management_paths(
        workload,
        service_account_email,
        service_account_member,
        keys,
        key_rings,
        ring_resources,
        resources_by_address,
        seen,
    )
    paths.extend(ring_paths)
    uncertainties.extend(ring_uncertainties)
    if _version_management_may_apply_to_member(
        service_account_member,
        keys,
        ring_resources,
        resources_by_address,
    ):
        uncertainties.extend(
            f"{workload.address}: Cloud KMS key version {version.address} has "
            "unresolved exact CryptoKey ancestry for management paths"
            for version in versions
            if version.address not in associated_version_addresses
        )

    paths.sort(
        key=lambda path: (
            path["target_resource_name"],
            path["management_effect"],
            path["operation"],
            path["iam_resource_address"],
            path["role"],
        )
    )
    return paths, dedupe(uncertainties)


def _version_management_may_apply_to_member(
    service_account_member: str,
    keys: Sequence[NormalizedResource],
    ring_resources: Mapping[str, tuple[NormalizedResource, ...]],
    resources_by_address: Mapping[str, NormalizedResource],
) -> bool:
    for key in keys:
        key_facts = gcp_facts(key)
        if any(
            _grant_may_authorize_version_management(grant, service_account_member) for grant in key_facts.kms_iam_grants
        ):
            return True
        if any(
            _iam_uncertainty_may_authorize_version_management(
                uncertainty,
                service_account_member,
                resources_by_address,
            )
            for uncertainty in key_facts.kms_iam_posture_uncertainties
        ):
            return True

    for candidates in ring_resources.values():
        for ring in candidates:
            ring_facts = gcp_facts(ring)
            if any(
                _grant_may_authorize_version_management(grant, service_account_member)
                for grant in ring_facts.kms_key_ring_iam_grants
            ):
                return True
            if any(
                _iam_uncertainty_may_authorize_version_management(
                    uncertainty,
                    service_account_member,
                    resources_by_address,
                )
                for uncertainty in ring_facts.kms_key_ring_iam_posture_uncertainties
            ):
                return True

    return False


def _grant_may_authorize_version_management(
    grant: Mapping[str, Any],
    service_account_member: str,
) -> bool:
    raw_members = grant.get("members")
    members = _string_list(raw_members)
    members_may_include_runtime = (
        service_account_member in members
        or grant.get("members_state") == "unknown"
        or not isinstance(raw_members, list)
        or not all(isinstance(member, str) and member for member in raw_members)
    )
    if not members_may_include_runtime:
        return False

    permissions = _string_list(grant.get("scope_effective_permissions"))
    if any(permission in _VERSION_MANAGEMENT_PERMISSIONS for permission in permissions):
        return True
    return _known_string(grant.get("role_resolution_state")) not in {"resolved", "modeled_subset"}


def _iam_uncertainty_may_authorize_version_management(
    uncertainty: str,
    service_account_member: str,
    resources_by_address: Mapping[str, NormalizedResource],
) -> bool:
    if not any(marker in uncertainty for marker in _UNRESOLVED_VERSION_MANAGEMENT_MARKERS):
        return False

    source = uncertainty.partition(":")[0]
    source_resource = resources_by_address.get(source)
    if source_resource is None:
        return True

    bindings = iam_bindings(source_resource)
    if not bindings:
        return True
    return any(_binding_may_include_member(binding, service_account_member) for binding in bindings)


def _binding_may_include_member(
    binding: Mapping[str, Any],
    service_account_member: str,
) -> bool:
    raw_members = binding.get("members")
    members = _string_list(raw_members)
    if service_account_member in members:
        return True
    if binding.get("members_state") == "unknown":
        return True
    return not (isinstance(raw_members, list) and all(isinstance(member, str) and member for member in raw_members))


def _standalone_key_ring_management_paths(
    workload: NormalizedResource,
    service_account_email: str,
    service_account_member: str,
    keys: Sequence[NormalizedResource],
    key_ring_resources: Sequence[NormalizedResource],
    ring_resources: Mapping[str, tuple[NormalizedResource, ...]],
    resources_by_address: Mapping[str, NormalizedResource],
    seen: set[tuple[str, str, str, str, str]],
) -> tuple[list[GcpCloudRunKmsManagementPath], list[str]]:
    paths: list[GcpCloudRunKmsManagementPath] = []
    uncertainties: list[str] = []
    for key_ring, candidates in sorted(ring_resources.items()):
        if len(candidates) != 1:
            uncertainties.append(
                f"{workload.address}: Cloud KMS key ring {key_ring} has "
                "multiple modeled resources for management-path projection"
            )
            continue
        ring = candidates[0]
        project = _project_from_key_ring_path(key_ring)
        if project is None:
            uncertainties.append(
                f"{workload.address}: Cloud KMS key ring {ring.address} has "
                "unresolved project ancestry for management-path projection"
            )
            continue

        ring_facts = gcp_facts(ring)
        sources_with_unresolved_members = {
            uncertainty.partition(":")[0]
            for uncertainty in (ring_facts.kms_key_ring_iam_posture_uncertainties)
            if "IAM members are unresolved" in uncertainty
        }
        sources_with_resolved_member_applicability: set[str] = set()
        sources_requiring_generic_uncertainty: set[str] = set()
        target = _ManagementTarget(
            target_type="key_ring",
            address=ring.address,
            resource_type=ring.resource_type,
            resource_name=key_ring,
            model_evidence_addresses=tuple(
                sorted(
                    {
                        ring.address,
                        *(
                            key.address
                            for key in keys
                            if ((identity := _key_identity(key)) is not None and identity.key_ring == key_ring)
                        ),
                    }
                )
            ),
            crypto_key_address=None,
            crypto_key_resource_name=None,
            key_version=None,
            lifecycle_compatibility_state="not_applicable",
        )
        for grant in ring_facts.kms_key_ring_iam_grants:
            source = _known_string(grant.get("source"))
            raw_members = grant.get("members")
            members = _string_list(raw_members)
            if (
                source is not None
                and source not in sources_with_unresolved_members
                and grant.get("members_state") != "unknown"
                and isinstance(raw_members, list)
                and all(isinstance(member, str) and member for member in raw_members)
            ):
                sources_with_resolved_member_applicability.add(source)
            if service_account_member not in members:
                continue

            permissions = _string_list(grant.get("scope_effective_permissions"))
            has_set_iam_policy = _KEY_RING_SET_IAM_POLICY_PERMISSION in permissions
            role_resolution_state = _known_string(grant.get("role_resolution_state"))
            if not has_set_iam_policy:
                if source is not None and role_resolution_state not in {"resolved", "modeled_subset"}:
                    sources_requiring_generic_uncertainty.add(source)
                continue

            role = _known_string(grant.get("role"))
            if not _grant_is_exact_for_key_ring(
                grant,
                ring,
                key_ring,
                project,
                resources_by_address,
            ):
                uncertainties.append(
                    f"{workload.address}: {source or ring.address} Cloud KMS "
                    f"IAM grant scope is unresolved for management of "
                    f"{key_ring}"
                )
                continue

            authorization_state = _known_string(grant.get("authorization_state"))
            management_state = _known_string(grant.get("management_state"))
            condition_state = _known_string(grant.get("condition_state"))
            if (
                authorization_state != "granted"
                or management_state != "unambiguous"
                or condition_state != "not_configured"
            ):
                uncertainties.append(
                    f"{workload.address}: {source or ring.address} has "
                    f"non-deterministic "
                    f"{_KEY_RING_SET_IAM_POLICY_PERMISSION} authority for "
                    f"{service_account_member} on {key_ring} "
                    f"(authorization_state="
                    f"{authorization_state or 'unknown'}, "
                    f"management_state={management_state or 'unknown'}, "
                    f"condition_state={condition_state or 'unknown'})"
                )
                continue

            fingerprint = (
                key_ring,
                source or "",
                role or "",
                _KEY_RING_SET_IAM_POLICY_PERMISSION,
                str(grant.get("scope")),
            )
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            paths.append(
                _management_path_record(
                    workload,
                    service_account_email,
                    service_account_member,
                    _KEY_RING_SET_IAM_POLICY_PERMISSION,
                    "authorization_administration",
                    "delegation",
                    target,
                    project,
                    key_ring,
                    grant,
                )
            )

        for uncertainty in ring_facts.kms_key_ring_iam_posture_uncertainties:
            source = uncertainty.partition(":")[0]
            if (
                source in sources_with_resolved_member_applicability
                and source not in sources_requiring_generic_uncertainty
            ):
                continue
            uncertainties.append(
                f"{workload.address}: Cloud KMS IAM posture for "
                f"{key_ring} is incomplete for management paths: "
                f"{uncertainty}"
            )

    exact_ring_addresses = {ring.address for candidates in ring_resources.values() for ring in candidates}
    for ring in key_ring_resources:
        if ring.address in exact_ring_addresses:
            continue
        ring_uncertainties = gcp_facts(ring).kms_key_ring_iam_posture_uncertainties
        if not ring_uncertainties:
            continue
        uncertainties.extend(
            f"{workload.address}: Cloud KMS IAM posture for "
            f"{ring.address} is incomplete for management paths: "
            f"{uncertainty}"
            for uncertainty in ring_uncertainties
        )

    return paths, dedupe(uncertainties)


def _grant_is_exact_for_key_ring(
    grant: GcpKmsManagementIamGrant,
    ring: NormalizedResource,
    key_ring: str,
    project: str,
    resources_by_address: Mapping[str, NormalizedResource],
) -> bool:
    source = _known_string(grant.get("source"))
    source_type = _known_string(grant.get("source_type"))
    if source is None or source_type not in (GCP_PROJECT_IAM_RESOURCE_TYPES | GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES):
        return False
    source_resource = resources_by_address.get(source)
    if source_resource is None or source_resource.resource_type != source_type:
        return False
    if grant.get("key_ring") != key_ring:
        return False
    if grant.get("project") != project:
        return False

    scope_type = grant["scope_type"]
    scope = _known_string(grant.get("scope"))
    if scope_type == "project":
        return scope == project
    if scope_type != "key_ring":
        return False
    if scope != key_ring:
        return False
    return ring.resource_type == GcpResourceType.KMS_KEY_RING


def _project_from_key_ring_path(key_ring: str) -> str | None:
    parts = key_ring.split("/")
    if (
        len(parts) == 6
        and parts[0] == "projects"
        and parts[1]
        and parts[2] == "locations"
        and parts[3]
        and parts[4] == "keyRings"
        and parts[5]
    ):
        return parts[1]
    return None


def _management_targets(
    permission: GcpKmsManagementPermission,
    target_type: GcpKmsManagementTargetType,
    key: NormalizedResource,
    identity: _KeyIdentity,
    version_records: Sequence[GcpKmsKeyVersionEvidence],
    keys: Sequence[NormalizedResource],
    ring_resources: Mapping[str, tuple[NormalizedResource, ...]],
    resources_by_address: Mapping[str, NormalizedResource],
) -> tuple[list[_ManagementTarget], list[str]]:
    if target_type == "crypto_key":
        return (
            [
                _ManagementTarget(
                    target_type=target_type,
                    address=key.address,
                    resource_type=key.resource_type,
                    resource_name=identity.path,
                    model_evidence_addresses=(key.address,),
                    crypto_key_address=key.address,
                    crypto_key_resource_name=identity.path,
                    key_version=None,
                    lifecycle_compatibility_state="not_applicable",
                )
            ],
            [],
        )

    if target_type == "key_ring":
        modeled_ring_resources = ring_resources.get(identity.key_ring, ())
        if len(modeled_ring_resources) > 1:
            return (
                [],
                [f"Cloud KMS key ring {identity.key_ring} has multiple modeled resources for {permission}"],
            )
        ring_resource = modeled_ring_resources[0] if modeled_ring_resources else None
        model_evidence_addresses = {
            candidate.address
            for candidate in keys
            if (
                (candidate_identity := _key_identity(candidate)) is not None
                and candidate_identity.key_ring == identity.key_ring
            )
        }
        if ring_resource is not None:
            model_evidence_addresses.add(ring_resource.address)
        return (
            [
                _ManagementTarget(
                    target_type=target_type,
                    address=(ring_resource.address if ring_resource is not None else None),
                    resource_type=GcpResourceType.KMS_KEY_RING,
                    resource_name=identity.key_ring,
                    model_evidence_addresses=tuple(sorted(model_evidence_addresses)),
                    crypto_key_address=None,
                    crypto_key_resource_name=None,
                    key_version=None,
                    lifecycle_compatibility_state="not_applicable",
                )
            ],
            [],
        )

    targets: list[_ManagementTarget] = []
    uncertainties: list[str] = []
    for record in version_records:
        version_address = record["version_address"]
        version_resource_name = record["version_resource_name"]
        version_resource = resources_by_address.get(version_address)
        if (
            record["version_identity_state"] != "resolved"
            or version_resource_name is None
            or version_resource is None
            or version_resource.resource_type != GcpResourceType.KMS_CRYPTO_KEY_VERSION
        ):
            uncertainties.append(
                f"Cloud KMS key version {version_address} has unresolved exact identity for {permission}"
            )
            continue
        lifecycle_compatibility = _version_management_lifecycle_compatibility(record["state"])
        if lifecycle_compatibility == "incompatible":
            continue
        if lifecycle_compatibility == "unknown":
            uncertainties.append(
                f"Cloud KMS key version {version_address} lifecycle state is unresolved for {permission}"
            )
            continue

        targets.append(
            _ManagementTarget(
                target_type=target_type,
                address=version_address,
                resource_type=version_resource.resource_type,
                resource_name=version_resource_name,
                model_evidence_addresses=(version_address,),
                crypto_key_address=key.address,
                crypto_key_resource_name=identity.path,
                key_version=record.copy(),
                lifecycle_compatibility_state="compatible",
            )
        )
    return targets, uncertainties


def _management_path_record(
    workload: NormalizedResource,
    service_account_email: str,
    service_account_member: str,
    permission: GcpKmsManagementPermission,
    operation_class: GcpKmsManagementOperationClass,
    management_effect: GcpKmsManagementEffect,
    target: _ManagementTarget,
    key_project: str,
    key_ring: str,
    grant: GcpKmsManagementIamGrant,
) -> GcpCloudRunKmsManagementPath:
    return {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "service_account_email": service_account_email,
        "service_account_member": service_account_member,
        "identity_kind": "cloud_run_service_account",
        "credential_context": "workload_runtime",
        "operation": permission,
        "operation_class": operation_class,
        "management_effect": management_effect,
        "matched_permissions": [permission],
        "target_type": target.target_type,
        "target_address": target.address,
        "target_resource_type": target.resource_type,
        "target_resource_name": target.resource_name,
        "target_model_evidence_addresses": list(target.model_evidence_addresses),
        "key_project": key_project,
        "key_ring": key_ring,
        "crypto_key_address": target.crypto_key_address,
        "crypto_key_resource_name": target.crypto_key_resource_name,
        "key_version": (target.key_version.copy() if target.key_version is not None else None),
        "lifecycle_compatibility_state": (target.lifecycle_compatibility_state),
        "iam_resource_address": grant["source"],
        "iam_resource_type": grant["source_type"],
        "role": grant["role"],
        "role_kind": grant["role_kind"],
        "role_resolution_state": grant["role_resolution_state"],
        "modeled_kms_permissions": list(grant["modeled_kms_permissions"]),
        "custom_role_permissions": list(grant.get("custom_role_permissions", [])),
        "role_definition_address": grant.get("role_definition_address"),
        "scope_effective_permissions": list(grant["scope_effective_permissions"]),
        "grant_members": list(grant["members"]),
        "grant_basis": grant["grant_basis"],
        "scope_type": grant["scope_type"],
        "scope": grant["scope"],
        "source_scope_reference": grant["source_scope_reference"],
        "management_mode": grant["management_mode"],
        "management_state": grant["management_state"],
        "condition": _mapping_copy(grant.get("condition")),
        "condition_state": grant["condition_state"],
        "authorization_state": "granted",
        "authorization_model": "cloud_kms_iam",
        "iam_scope_is_key_version": False,
        "iam_grant_record": grant.copy(),
    }


def _version_management_lifecycle_compatibility(
    state: str | None,
) -> str:
    if state is None:
        return "unknown"
    if state.strip().upper() in {"ENABLED", "DISABLED"}:
        return "compatible"
    return "incompatible"


def _key_ring_resources_by_path(
    resources: Sequence[NormalizedResource],
) -> dict[str, tuple[NormalizedResource, ...]]:
    grouped: dict[str, list[NormalizedResource]] = {}
    for resource in resources:
        if resource.resource_type != GcpResourceType.KMS_KEY_RING:
            continue
        facts = gcp_facts(resource)
        ring_path = next(
            (
                text.rstrip("/")
                for value in (facts.kms_key_ring, resource.identifier)
                if (text := _known_string(value)) is not None
                and _KEY_RING_PATH_PATTERN.fullmatch(text.rstrip("/")) is not None
            ),
            None,
        )
        if ring_path is not None:
            grouped.setdefault(ring_path, []).append(resource)
    return {
        ring_path: tuple(sorted(candidates, key=lambda candidate: candidate.address))
        for ring_path, candidates in grouped.items()
    }


def _grant_is_exact_for_key(
    grant: GcpKmsIamGrant,
    key: NormalizedResource,
    identity: _KeyIdentity,
    resources_by_address: Mapping[str, NormalizedResource],
) -> bool:
    source = _known_string(grant.get("source"))
    source_type = _known_string(grant.get("source_type"))
    if source is None or source_type not in _IAM_RESOURCE_TYPES:
        return False
    source_resource = resources_by_address.get(source)
    if source_resource is None or source_resource.resource_type != source_type:
        return False
    if grant.get("crypto_key_address") != key.address:
        return False
    if grant.get("crypto_key") != identity.path:
        return False
    if grant.get("project") != identity.project:
        return False
    if grant.get("key_ring") != identity.key_ring:
        return False

    scope_type = grant["scope_type"]
    scope = _known_string(grant.get("scope"))
    expected_scopes: dict[GcpKmsScopeType, str] = {
        "project": identity.project,
        "key_ring": identity.key_ring,
        "crypto_key": identity.path,
    }
    expected_scope = expected_scopes[scope_type]
    return expected_scope is not None and scope == expected_scope


def _operation_class(
    permission: GcpKmsOperationPermission,
    purpose: str | None,
) -> GcpKmsOperationClass | None:
    if purpose is None:
        return None
    if permission == _DECRYPT_PERMISSION:
        return "decrypt" if purpose == "ENCRYPT_DECRYPT" else None
    if permission == _SIGN_PERMISSION:
        if purpose == "ASYMMETRIC_SIGN":
            return "sign"
        if purpose == "MAC":
            return "mac_generation"
    return None


def _operation_path_record(
    workload: NormalizedResource,
    key: NormalizedResource,
    identity: _KeyIdentity,
    service_account_email: str,
    service_account_member: str,
    permission: GcpKmsOperationPermission,
    operation_class: GcpKmsOperationClass,
    grant: GcpKmsIamGrant,
    version_records: list[GcpKmsKeyVersionEvidence],
) -> GcpCloudRunKmsOperationPath:
    return {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "service_account_email": service_account_email,
        "service_account_member": service_account_member,
        "identity_kind": "cloud_run_service_account",
        "credential_context": "workload_runtime",
        "key_address": key.address,
        "key_resource_type": key.resource_type,
        "key_resource_name": identity.path,
        "key_project": identity.project,
        "key_ring": identity.key_ring,
        "key_purpose": identity.purpose,
        "operation": permission,
        "operation_class": operation_class,
        "matched_permissions": [permission],
        "iam_resource_address": grant.get("source"),
        "iam_resource_type": grant.get("source_type"),
        "role": grant.get("role"),
        "role_kind": grant.get("role_kind"),
        "role_resolution_state": grant.get("role_resolution_state"),
        "modeled_kms_permissions": list(_string_list(grant.get("modeled_kms_permissions"))),
        "custom_role_permissions": list(_string_list(grant.get("custom_role_permissions"))),
        "role_definition_address": grant.get("role_definition_address"),
        "scope_effective_permissions": list(_string_list(grant.get("scope_effective_permissions"))),
        "grant_members": list(_string_list(grant.get("members"))),
        "grant_basis": grant.get("grant_basis"),
        "scope_type": grant.get("scope_type"),
        "scope": grant.get("scope"),
        "source_scope_reference": grant.get("source_scope_reference"),
        "management_mode": grant.get("management_mode"),
        "management_state": grant.get("management_state"),
        "condition": _mapping_copy(grant.get("condition")),
        "condition_state": grant.get("condition_state"),
        "authorization_state": grant.get("authorization_state"),
        "authorization_model": "cloud_kms_iam",
        "key_versions": [record.copy() for record in version_records],
        "key_version_evidence_scope": "modeled_versions_of_crypto_key",
        "iam_scope_is_key_version": False,
        "iam_grant_record": grant.copy(),
    }


def _key_identity(key: NormalizedResource) -> _KeyIdentity | None:
    facts = gcp_facts(key)
    key_path = next(
        (
            text
            for value in (facts.kms_crypto_key_reference, key.identifier)
            if (text := _known_string(value)) is not None and _KEY_PATH_PATTERN.fullmatch(text.rstrip("/")) is not None
        ),
        None,
    )
    if key_path is None:
        return None
    key_path = key_path.rstrip("/")
    match = _KEY_PATH_PATTERN.fullmatch(key_path)
    if match is None:
        return None
    key_ring = key_path.rsplit("/cryptoKeys/", 1)[0]
    purpose = None if _key_purpose_is_unknown(key) else (facts.kms_purpose or "ENCRYPT_DECRYPT").strip().upper()
    return _KeyIdentity(
        path=key_path,
        key_ring=key_ring,
        project=match.group("project"),
        purpose=purpose or None,
    )


def _key_purpose_is_unknown(key: NormalizedResource) -> bool:
    return any(
        "purpose is unknown after planning" in uncertainty for uncertainty in gcp_facts(key).kms_posture_uncertainties
    )


def _key_version_records(
    key: NormalizedResource,
    key_path: str,
    versions: Sequence[NormalizedResource],
) -> list[GcpKmsKeyVersionEvidence]:
    records: list[GcpKmsKeyVersionEvidence] = []
    for version in versions:
        facts = gcp_facts(version)
        if facts.kms_crypto_key_version_resolved_key_address != key.address:
            continue
        version_path = _known_string(facts.kms_crypto_key_version_reference or version.identifier)
        match = _VERSION_PATH_PATTERN.fullmatch(version_path or "")
        identity_state = "resolved" if match is not None and match.group("key_path") == key_path else "unknown"
        records.append(
            {
                "version_address": version.address,
                "version_resource_type": version.resource_type,
                "version_resource_name": version_path if identity_state == "resolved" else None,
                "version_identity_state": identity_state,
                "version_number": facts.kms_crypto_key_version_number,
                "purpose": facts.kms_crypto_key_version_purpose,
                "algorithm": facts.kms_crypto_key_version_algorithm,
                "protection_level": facts.kms_crypto_key_version_protection_level,
                "state": facts.kms_crypto_key_version_state,
                "import_posture": facts.kms_crypto_key_version_import_posture,
                "generate_time": facts.kms_crypto_key_version_generate_time,
                "rotation_period": facts.kms_crypto_key_version_rotation_period,
                "destroy_scheduled_duration": (facts.kms_crypto_key_version_destroy_scheduled_duration),
                "deletion_policy": facts.kms_crypto_key_version_deletion_policy,
                "deletion_policy_state": (facts.kms_crypto_key_version_deletion_policy_state),
                "posture_uncertainties": list(facts.kms_crypto_key_version_posture_uncertainties),
            }
        )
    records.sort(
        key=lambda record: (
            str(record["version_resource_name"]),
            str(record["version_address"]),
        )
    )
    return records


def _is_exact_service_account_identity(
    email: str | None,
    member: str | None,
) -> bool:
    if email is None or member is None:
        return False
    if "@" not in email or not email.endswith(".gserviceaccount.com"):
        return False
    if "${" in email or ("google_" in email and "." in email):
        return False
    return member == f"serviceAccount:{email}"


def _is_relevant_permission(value: str) -> TypeGuard[GcpKmsOperationPermission]:
    return value != _DELEGATED_DECRYPT_PERMISSION and value in _RELEVANT_PERMISSIONS


def _is_management_permission(
    value: str,
) -> TypeGuard[GcpKmsManagementPermission]:
    return value in _MANAGEMENT_PERMISSIONS


def _mapping_copy(value: object) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    return {str(key): item for key, item in value.items()}


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None
