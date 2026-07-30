from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.coercion import dedupe
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext
from tfstride.providers.gcp.resource_types import (
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES,
    GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GcpResourceType,
)

_DECRYPT_PERMISSION = "cloudkms.cryptoKeyVersions.useToDecrypt"
_DELEGATED_DECRYPT_PERMISSION = "cloudkms.cryptoKeyVersions.useToDecryptViaDelegation"
_SIGN_PERMISSION = "cloudkms.cryptoKeyVersions.useToSign"
_RELEVANT_PERMISSIONS = frozenset({_DECRYPT_PERMISSION, _SIGN_PERMISSION})
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


@dataclass(frozen=True, slots=True)
class _KeyIdentity:
    path: str
    key_ring: str
    project: str
    purpose: str | None


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


def _cloud_run_kms_operation_paths(
    workload: NormalizedResource,
    keys: Sequence[NormalizedResource],
    versions: Sequence[NormalizedResource],
    resources_by_address: Mapping[str, NormalizedResource],
) -> tuple[list[dict[str, Any]], list[str]]:
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

    paths: list[dict[str, Any]] = []
    uncertainties: list[str] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for key in keys:
        identity = _key_identity(key)
        if identity is None:
            uncertainties.append(f"{workload.address}: Cloud KMS key {key.address} has unresolved exact ancestry")
            continue

        key_facts = gcp_facts(key)
        version_records = _key_version_records(key, identity.path, versions)
        sources_with_unresolved_members = {
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
            candidate_permissions = [
                permission
                for permission in permissions
                if permission != _DELEGATED_DECRYPT_PERMISSION and permission in _RELEVANT_PERMISSIONS
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


def _grant_is_exact_for_key(
    grant: Mapping[str, object],
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

    scope_type = _known_string(grant.get("scope_type"))
    scope = _known_string(grant.get("scope"))
    expected_scope = {
        "project": identity.project,
        "key_ring": identity.key_ring,
        "crypto_key": identity.path,
    }.get(scope_type or "")
    return expected_scope is not None and scope == expected_scope


def _operation_class(permission: str, purpose: str | None) -> str | None:
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
    permission: str,
    operation_class: str,
    grant: Mapping[str, object],
    version_records: list[dict[str, Any]],
) -> dict[str, Any]:
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
        "key_versions": [dict(record) for record in version_records],
        "key_version_evidence_scope": "modeled_versions_of_crypto_key",
        "iam_scope_is_key_version": False,
        "iam_grant_record": dict(grant),
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
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
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
