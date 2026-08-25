from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, cast

from tfstride.models import NormalizedResource
from tfstride.providers.azure.arm_control_plane_authorization import (
    AzureArmControlPlaneAuthorityResult,
    model_arm_control_plane_action_authority,
)
from tfstride.providers.azure.arm_control_plane_evidence import AzureArmControlPlaneGrant
from tfstride.providers.azure.key_vault_evidence import AzureKeyVaultRuntimeIdentityKind
from tfstride.providers.azure.object_storage_topology_destruction_evidence import (
    AzureAppServiceStorageContainerTopologyDestructionCompatiblePath,
    AzureAppServiceStorageContainerTopologyDestructionPath,
    AzureAppServiceStorageContainerTopologyDestructionPathCommon,
    AzureAppServiceStorageContainerTopologyDestructionUnknownPath,
    AzureStorageContainerSoftDeleteDisabledRecoveryEvidence,
    AzureStorageContainerSoftDeleteEnabledRecoveryEvidence,
    AzureStorageContainerSoftDeleteUnknownRecoveryEvidence,
    AzureStorageContainerTopologyBuiltInRoleEvidence,
    AzureStorageContainerTopologyCustomRoleEvidence,
    AzureStorageContainerTopologyDeletionConstraintEvidence,
    AzureStorageContainerTopologyDeletionConstraintsCompatible,
    AzureStorageContainerTopologyDeletionConstraintsUnknown,
    AzureStorageContainerTopologyDestructionAuthorizationGrant,
    AzureStorageContainerTopologyDestructionRecoveryEvidence,
    AzureStorageContainerTopologyDestructionRecoveryEvidenceCommon,
    AzureStorageContainerTopologyRoleEvidence,
)
from tfstride.providers.azure.resource_decoration.workload_identities import workload_managed_identities
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import AZURE_APP_SERVICE_RESOURCE_TYPES, AzureResourceType
from tfstride.providers.coercion import dedupe, dedupe_strings

_DELETE_CONTAINER: Literal["Microsoft.Storage/storageAccounts/blobServices/containers/delete"] = (
    "Microsoft.Storage/storageAccounts/blobServices/containers/delete"
)
_STORAGE_ACCOUNT_ID_PATTERN = re.compile(
    r"^/subscriptions/[^/]+/resourcegroups/[^/]+/providers/"
    r"microsoft\.storage/storageaccounts/[^/]+$",
    re.IGNORECASE,
)
_STORAGE_CONTAINER_ID_PATTERN = re.compile(
    r"^/subscriptions/[^/]+/resourcegroups/[^/]+/providers/"
    r"microsoft\.storage/storageaccounts/[^/]+/blobservices/default/containers/[^/]+$",
    re.IGNORECASE,
)
_CONSTRAINT_UNCERTAINTY_PREFIXES = (
    "has_immutability_policy ",
    "has_legal_hold ",
)
_RECOVERY_UNCERTAINTY_PREFIX = "blob_properties.container_delete_retention_policy"

_ConstraintState = Literal["compatible", "unknown"]


@dataclass(frozen=True, slots=True)
class _RuntimeIdentity:
    resource: NormalizedResource
    kind: AzureKeyVaultRuntimeIdentityKind
    principal_id: str


@dataclass(frozen=True, slots=True)
class _ContainerTarget:
    container: NormalizedResource
    container_name: str
    container_id: str
    account: NormalizedResource
    account_id: str


@dataclass(frozen=True, slots=True)
class _ConstraintEvaluation:
    state: _ConstraintState
    evidence: AzureStorageContainerTopologyDeletionConstraintEvidence


class ModelAppServiceStorageContainerTopologyDestructionPathsStage:
    """Project deterministic container-deletion authority onto App Services."""

    name = "model_app_service_storage_container_topology_destruction_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AzureDecorationContext,
    ) -> None:
        targets, target_uncertainties = _container_targets(resources, context)
        assignments = tuple(
            resource for resource in resources if resource.resource_type == AzureResourceType.ROLE_ASSIGNMENT
        )
        for workload in resources:
            if workload.resource_type not in AZURE_APP_SERVICE_RESOURCE_TYPES:
                continue
            paths, uncertainties = _app_service_storage_container_topology_destruction_paths(
                workload,
                targets,
                target_uncertainties,
                assignments,
                context,
            )
            facts = azure_facts(workload)
            facts.set_app_service_storage_container_topology_destruction_paths(paths)
            facts.extend_app_service_storage_container_topology_destruction_path_uncertainties(
                uncertainties,
            )


def current_app_service_storage_container_topology_destruction_paths(
    workload: NormalizedResource,
    container: NormalizedResource,
    resources: Sequence[NormalizedResource],
    context: AzureDecorationContext,
) -> list[AzureAppServiceStorageContainerTopologyDestructionPath]:
    """Recompute every current deterministic proof for one workload and container."""

    if (
        workload.resource_type not in AZURE_APP_SERVICE_RESOURCE_TYPES
        or container.resource_type != AzureResourceType.STORAGE_CONTAINER
    ):
        return []
    target, _uncertainty = _container_target(container, context)
    if target is None:
        return []
    paths, _uncertainties = _app_service_storage_container_topology_destruction_paths(
        workload,
        (target,),
        (),
        tuple(resource for resource in resources if resource.resource_type == AzureResourceType.ROLE_ASSIGNMENT),
        context,
    )
    return paths


def _app_service_storage_container_topology_destruction_paths(
    workload: NormalizedResource,
    targets: Sequence[_ContainerTarget],
    target_uncertainties: Sequence[str],
    assignments: Sequence[NormalizedResource],
    context: AzureDecorationContext,
) -> tuple[list[AzureAppServiceStorageContainerTopologyDestructionPath], list[str]]:
    identities, identity_uncertainties = workload_managed_identities(workload, context)
    uncertainties = [
        *identity_uncertainties,
        *(f"{workload.address}: {value}" for value in azure_facts(workload).managed_identity_uncertainties),
        *(f"{workload.address}: {value}" for value in target_uncertainties),
    ]
    runtime_identities = tuple(
        _RuntimeIdentity(identity, kind, principal_id)
        for identity, kind in identities
        if (principal_id := _known_string(azure_facts(identity).principal_id)) is not None
    )
    if not runtime_identities:
        return [], dedupe(uncertainties)

    paths: list[AzureAppServiceStorageContainerTopologyDestructionPath] = []
    for target in targets:
        constraint = _constraint_evaluation(target.container)
        recovery = _recovery_evidence(target.account)

        for identity in runtime_identities:
            for assignment in assignments:
                result = model_arm_control_plane_action_authority(
                    assignment,
                    context,
                    principal_id=identity.principal_id,
                    target_arm_id=target.container_id,
                    requested_actions=(_DELETE_CONTAINER,),
                )
                _record_authorization_uncertainties(
                    workload,
                    target,
                    result,
                    uncertainties,
                )
                if result.grant is None:
                    continue
                path = _topology_path(
                    workload,
                    identity,
                    target,
                    result.grant,
                    constraint,
                    recovery,
                )
                if path is None:
                    uncertainties.append(
                        f"{workload.address}: {assignment.address} returned incoherent "
                        f"container-deletion evidence for {target.container.address}"
                    )
                    continue
                paths.append(path)
                uncertainties.extend(
                    f"{workload.address}: {target.container.address}: {value}"
                    for value in path["posture_uncertainties"]
                )

    paths.sort(
        key=lambda path: (
            path["container_address"],
            path["identity_address"],
            path["role_assignment_address"],
        )
    )
    return _dedupe_paths(paths), dedupe(uncertainties)


def _record_authorization_uncertainties(
    workload: NormalizedResource,
    target: _ContainerTarget,
    result: AzureArmControlPlaneAuthorityResult,
    uncertainties: list[str],
) -> None:
    if result.state != "unknown":
        return
    uncertainties.extend(f"{workload.address}: {target.container.address}: {value}" for value in result.uncertainties)


def _container_targets(
    resources: Sequence[NormalizedResource],
    context: AzureDecorationContext,
) -> tuple[list[_ContainerTarget], list[str]]:
    targets: list[_ContainerTarget] = []
    uncertainties: list[str] = []
    for resource in resources:
        if resource.resource_type != AzureResourceType.STORAGE_CONTAINER:
            continue
        target, uncertainty = _container_target(resource, context)
        if target is not None:
            targets.append(target)
        elif uncertainty is not None:
            uncertainties.append(uncertainty)
    targets.sort(key=lambda target: target.container.address)
    return targets, dedupe(uncertainties)


def _container_target(
    container: NormalizedResource,
    context: AzureDecorationContext,
) -> tuple[_ContainerTarget | None, str | None]:
    facts = azure_facts(container)
    account = context.index.resources_by_address.get(
        facts.resolved_storage_account_address or "",
    )
    if account is None or account.resource_type != AzureResourceType.STORAGE_ACCOUNT:
        return None, f"{container.address}: exact Storage Account ancestry is unresolved"

    account_id = _exact_account_id(azure_facts(account).storage_account_id)
    container_id = _exact_container_id(facts.storage_container_resource_manager_id)
    container_name = _known_string(facts.bucket_name)
    if account_id is None or container_id is None or container_name is None:
        return None, f"{container.address}: exact container ARM identity is unresolved"
    expected_id = f"{account_id}/blobServices/default/containers/{container_name}"
    if not _same_identifier(container_id, expected_id):
        return None, f"{container.address}: container ARM identity and Storage Account ancestry are incoherent"
    return (
        _ContainerTarget(
            container=container,
            container_name=container_name,
            container_id=container_id,
            account=account,
            account_id=account_id,
        ),
        None,
    )


def _constraint_evaluation(container: NormalizedResource) -> _ConstraintEvaluation:
    facts = azure_facts(container)
    immutability = facts.storage_container_has_immutability_policy
    legal_hold = facts.storage_container_has_legal_hold
    uncertainties = [
        value for value in facts.storage_posture_uncertainties if value.startswith(_CONSTRAINT_UNCERTAINTY_PREFIXES)
    ]
    if immutability is True or legal_hold is True:
        uncertainties.append(
            "protected-content emptiness required by container immutability or legal-hold posture is not established"
        )
        return _ConstraintEvaluation(
            "unknown",
            AzureStorageContainerTopologyDeletionConstraintsUnknown(
                constraint_evidence_scope="plan_local_storage_container_immutability_and_legal_hold",
                has_immutability_policy=immutability,
                has_legal_hold=legal_hold,
                constraint_state="protected_content_emptiness_not_established",
                protected_content_emptiness_required=True,
                protected_content_emptiness_state="not_established",
                arm_management_lock_applicability="not_applicable_to_storage_container_deletion",
                uncertainties=dedupe(uncertainties),
            ),
        )
    if immutability is None or legal_hold is None:
        if not uncertainties:
            uncertainties.append("container immutability or legal-hold posture is unresolved")
        return _ConstraintEvaluation(
            "unknown",
            AzureStorageContainerTopologyDeletionConstraintsUnknown(
                constraint_evidence_scope="plan_local_storage_container_immutability_and_legal_hold",
                has_immutability_policy=immutability,
                has_legal_hold=legal_hold,
                constraint_state="unknown",
                protected_content_emptiness_required=None,
                protected_content_emptiness_state="unknown",
                arm_management_lock_applicability="not_applicable_to_storage_container_deletion",
                uncertainties=dedupe(uncertainties),
            ),
        )
    return _ConstraintEvaluation(
        "compatible",
        AzureStorageContainerTopologyDeletionConstraintsCompatible(
            constraint_evidence_scope="plan_local_storage_container_immutability_and_legal_hold",
            has_immutability_policy=False,
            has_legal_hold=False,
            constraint_state="not_observed",
            protected_content_emptiness_required=False,
            protected_content_emptiness_state="not_applicable",
            arm_management_lock_applicability="not_applicable_to_storage_container_deletion",
            uncertainties=[],
        ),
    )


def _recovery_evidence(
    account: NormalizedResource,
) -> AzureStorageContainerTopologyDestructionRecoveryEvidence:
    facts = azure_facts(account)
    uncertainties = [
        value for value in facts.storage_posture_uncertainties if value.startswith(_RECOVERY_UNCERTAINTY_PREFIX)
    ]
    common: AzureStorageContainerTopologyDestructionRecoveryEvidenceCommon = {
        "recovery_evidence_scope": "azure_storage_container_soft_delete",
        "successful_deletion_observed": False,
        "restoration_observed": False,
        "storage_account_deletion_evaluated": False,
        "out_of_plan_blob_inventory_evaluated": False,
        "uncertainties": dedupe(uncertainties),
    }
    days = facts.storage_container_delete_retention_days
    if uncertainties:
        return AzureStorageContainerSoftDeleteUnknownRecoveryEvidence(
            **common,
            container_soft_delete_state="unknown",
            container_delete_retention_days=None,
            container_recovery_state="unknown",
        )
    if isinstance(days, int) and days > 0:
        return AzureStorageContainerSoftDeleteEnabledRecoveryEvidence(
            **common,
            container_soft_delete_state="enabled",
            container_delete_retention_days=days,
            container_recovery_state="soft_delete_recovery_configured",
        )
    return AzureStorageContainerSoftDeleteDisabledRecoveryEvidence(
        **common,
        container_soft_delete_state="disabled",
        container_delete_retention_days=None,
        container_recovery_state="not_established_by_modeled_azure_storage_container_evidence",
    )


def _topology_path(
    workload: NormalizedResource,
    identity: _RuntimeIdentity,
    target: _ContainerTarget,
    grant: AzureArmControlPlaneGrant,
    constraint: _ConstraintEvaluation,
    recovery: AzureStorageContainerTopologyDestructionRecoveryEvidence,
) -> AzureAppServiceStorageContainerTopologyDestructionPath | None:
    authorization = _authorization_grant(grant, identity, target)
    if authorization is None:
        return None
    role_definition_address = authorization["role_evidence"]["role_definition_address"]
    common = AzureAppServiceStorageContainerTopologyDestructionPathCommon(
        workload_address=workload.address,
        workload_type=workload.resource_type,
        identity_address=identity.resource.address,
        identity_kind=identity.kind,
        principal_id=identity.principal_id,
        credential_context="workload_runtime",
        storage_account_address=target.account.address,
        storage_account_id=target.account_id,
        container_address=target.container.address,
        container_name=target.container_name,
        container_resource_manager_id=target.container_id,
        operation=_DELETE_CONTAINER,
        operation_class="container_deletion",
        internal_operation="delete_container",
        management_effect="disruption",
        authorization_evidence_kind="azure_rbac_action",
        target_granularity="container_topology",
        target_scope="exact_storage_container",
        target_model_evidence_addresses=[target.account.address, target.container.address],
        role_assignment_address=authorization["source_address"],
        authorization_source_addresses=dedupe_strings(
            [authorization["source_address"], role_definition_address],
        ),
        authorization_state="granted",
        modeled_allow_evidence_complete=True,
        condition=None,
        condition_state="not_configured",
        authorization_grant=authorization,
        recovery_evidence=recovery,
        posture_uncertainties=dedupe(
            [
                *constraint.evidence["uncertainties"],
                *recovery["uncertainties"],
            ]
        ),
    )
    if constraint.state == "compatible":
        return AzureAppServiceStorageContainerTopologyDestructionCompatiblePath(
            **common,
            lifecycle_compatibility_state="compatible",
            deletion_constraint_evidence=cast(
                AzureStorageContainerTopologyDeletionConstraintsCompatible,
                constraint.evidence,
            ),
        )
    return AzureAppServiceStorageContainerTopologyDestructionUnknownPath(
        **common,
        lifecycle_compatibility_state="unknown",
        deletion_constraint_evidence=cast(
            AzureStorageContainerTopologyDeletionConstraintsUnknown,
            constraint.evidence,
        ),
    )


def _authorization_grant(
    grant: AzureArmControlPlaneGrant,
    identity: _RuntimeIdentity,
    target: _ContainerTarget,
) -> AzureStorageContainerTopologyDestructionAuthorizationGrant | None:
    principal_id = _known_string(grant["principal_id"])
    role_evidence = _role_evidence(grant)
    if (
        principal_id is None
        or not _same_identifier(principal_id, identity.principal_id)
        or not _same_identifier(grant["target_arm_id"], target.container_id)
        or grant["requested_actions"] != [_DELETE_CONTAINER]
        or grant["matched_actions"] != [_DELETE_CONTAINER]
        or grant["excluded_actions"]
        or grant["principal_state"] != "resolved"
        or grant["assignment_scope_state"] != "resolved"
        or grant["assignment_condition"] is not None
        or grant["assignment_condition_version"] is not None
        or grant["assignment_condition_state"] != "not_configured"
        or grant["role_definition_condition_state"] != "not_configured"
        or grant["delegation_constraint_kind"] != "none"
        or grant["allowed_role_definition_ids"]
        or grant["authorization_state"] != "granted"
        or grant["deny_assignments_evaluated"] is not False
        or grant["evaluation_basis"] != "modeled_arm_control_plane_authority"
        or role_evidence is None
    ):
        return None
    return AzureStorageContainerTopologyDestructionAuthorizationGrant(
        source_address=grant["source_address"],
        principal_id=principal_id,
        principal_type=grant["principal_type"],
        principal_state="resolved",
        assignment_scope_type=grant["assignment_scope_type"],
        assignment_scope=grant["assignment_scope"],
        assignment_scope_arm_id=grant["assignment_scope_arm_id"],
        assignment_scope_state="resolved",
        target_arm_id=target.container_id,
        role_definition_name=grant["role_definition_name"],
        role_definition_id=grant["role_definition_id"],
        role_evidence=role_evidence,
        role_actions=list(grant["role_actions"]),
        role_not_actions=list(grant["role_not_actions"]),
        requested_actions=[_DELETE_CONTAINER],
        matched_actions=[_DELETE_CONTAINER],
        excluded_actions=[],
        assignment_condition=None,
        assignment_condition_version=None,
        assignment_condition_state="not_configured",
        role_definition_condition_state="not_configured",
        delegation_constraint_kind="none",
        allowed_role_definition_ids=[],
        authorization_state="granted",
        deny_assignments_evaluated=False,
        evaluation_basis="modeled_azure_rbac_action_authority",
    )


def _role_evidence(
    grant: AzureArmControlPlaneGrant,
) -> AzureStorageContainerTopologyRoleEvidence | None:
    role_definition_address = _known_string(grant["role_definition_address"])
    if (
        grant["role_kind"] == "built_in"
        and grant["role_resolution_state"] == "modeled_subset"
        and role_definition_address is None
        and grant["assignable_scope_compatibility_state"] == "not_applicable"
    ):
        return AzureStorageContainerTopologyBuiltInRoleEvidence(
            role_kind="built_in",
            role_resolution_state="modeled_subset",
            role_definition_address=None,
            assignable_scope_compatibility_state="not_applicable",
        )
    if (
        grant["role_kind"] == "custom"
        and grant["role_resolution_state"] == "resolved"
        and role_definition_address is not None
        and grant["assignable_scope_compatibility_state"] == "resolved"
    ):
        return AzureStorageContainerTopologyCustomRoleEvidence(
            role_kind="custom",
            role_resolution_state="resolved",
            role_definition_address=role_definition_address,
            assignable_scope_compatibility_state="resolved",
        )
    return None


def _exact_account_id(value: object) -> str | None:
    normalized = _known_arm_id(value)
    if normalized is None or _STORAGE_ACCOUNT_ID_PATTERN.fullmatch(normalized) is None:
        return None
    return normalized


def _exact_container_id(value: object) -> str | None:
    normalized = _known_arm_id(value)
    if normalized is None or _STORAGE_CONTAINER_ID_PATTERN.fullmatch(normalized) is None:
        return None
    return normalized


def _known_arm_id(value: object) -> str | None:
    normalized = _known_string(value)
    if normalized is None or not normalized.startswith("/"):
        return None
    return normalized.rstrip("/")


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _same_identifier(left: object, right: object) -> bool:
    left_value = _known_string(left)
    right_value = _known_string(right)
    return bool(left_value and right_value and left_value.rstrip("/").casefold() == right_value.rstrip("/").casefold())


def _dedupe_paths(
    paths: Sequence[AzureAppServiceStorageContainerTopologyDestructionPath],
) -> list[AzureAppServiceStorageContainerTopologyDestructionPath]:
    result: list[AzureAppServiceStorageContainerTopologyDestructionPath] = []
    for path in paths:
        if path not in result:
            result.append(path)
    return result
