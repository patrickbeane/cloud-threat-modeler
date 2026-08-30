from __future__ import annotations

from collections.abc import Sequence
from typing import Literal, TypedDict

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.constants import PUBLIC_GCP_IAM_MEMBERS
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_decoration.iam import (
    iam_bindings,
    resource_iam_target_reference,
)
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import gcp_resource_references
from tfstride.providers.gcp.resource_types import (
    GCP_CLOUD_RUN_IAM_RESOURCE_TYPES,
    GCP_CLOUD_RUN_RESOURCE_TYPES,
)
from tfstride.providers.gcp.resource_utils import (
    GCP_NETWORK_REFERENCE_SUFFIXES,
    binding_members,
    gcp_reference_key,
)

_PUBLIC_INVOKER_ROLES = frozenset(
    {
        "roles/run.invoker",
        "roles/run.servicesInvoker",
    }
)

_IamManagementMode = Literal[
    "authoritative_policy",
    "authoritative_role_binding",
    "additive_member",
]
_IamManager = tuple[
    NormalizedResource,
    _IamManagementMode,
    tuple[str, ...],
]


class CloudRunPublicInvokerBinding(TypedDict):
    source: str
    role: str
    member: str


def current_cloud_run_public_invokers(
    workload: NormalizedResource,
    current_resources: Sequence[NormalizedResource],
) -> list[CloudRunPublicInvokerBinding]:
    managers: list[_IamManager] = []
    unresolved_authoritative_roles: set[str] = set()
    unresolved_authoritative_scope = False

    for iam_resource in current_resources:
        if iam_resource.resource_type not in GCP_CLOUD_RUN_IAM_RESOURCE_TYPES:
            continue
        target_state = _cloud_run_iam_target_state(
            iam_resource,
            workload,
            current_resources,
        )
        if target_state == "unrelated":
            continue

        management_mode = _cloud_run_iam_management_mode(iam_resource)
        roles = _cloud_run_iam_manager_roles(iam_resource)
        manager_state = _cloud_run_iam_manager_state(
            iam_resource,
            management_mode,
        )
        if target_state == "unknown" or manager_state == "unknown":
            if management_mode == "authoritative_policy":
                unresolved_authoritative_scope = True
            elif management_mode == "authoritative_role_binding":
                if roles:
                    unresolved_authoritative_roles.update(roles)
                else:
                    unresolved_authoritative_scope = True
            continue

        managers.append((iam_resource, management_mode, roles))
        if management_mode == "authoritative_role_binding" and not roles:
            unresolved_authoritative_scope = True

    if unresolved_authoritative_scope or _cloud_run_iam_scope_is_ambiguous(
        managers,
    ):
        return []

    ambiguous_roles = _cloud_run_iam_ambiguous_roles(managers)
    ambiguous_roles.update(unresolved_authoritative_roles)
    invokers: dict[
        tuple[str, str, str],
        CloudRunPublicInvokerBinding,
    ] = {}
    for iam_resource, _management_mode, _roles in managers:
        for binding in iam_bindings(iam_resource):
            role = _known_string(binding.get("role"))
            if (
                role not in _PUBLIC_INVOKER_ROLES
                or role in ambiguous_roles
                or binding.get("role_state") == "unknown"
                or binding.get("members_state") == "unknown"
                or binding.get("condition")
                or binding.get("condition_state") not in {None, "not_configured"}
            ):
                continue
            for member in binding_members(binding):
                if member not in PUBLIC_GCP_IAM_MEMBERS:
                    continue
                key = (iam_resource.address, role, member)
                invokers[key] = {
                    "source": iam_resource.address,
                    "role": role,
                    "member": member,
                }
    return [invokers[key] for key in sorted(invokers)]


def current_cloud_run_public_exposure_reasons(
    workload: NormalizedResource,
    public_invokers: Sequence[CloudRunPublicInvokerBinding],
    *,
    invoker_iam_check_disabled: bool,
) -> list[str]:
    reasons: list[str] = []
    if invoker_iam_check_disabled:
        reasons.append(f"{workload.address} disables the Cloud Run Invoker IAM check")
    reasons.extend(
        f"{binding['source']} grants {binding['role']} to {binding['member']}" for binding in public_invokers
    )
    return reasons


def cloud_run_public_exposure_configuration(
    workload: NormalizedResource,
) -> list[str]:
    if gcp_facts(workload).cloud_run_invoker_iam_disabled is not True:
        return []
    ingress = gcp_facts(workload).serverless_ingress or "unknown"
    return [f"invoker_iam_check=disabled; ingress={ingress}"]


def cloud_run_public_invoker_evidence(
    public_invokers: Sequence[CloudRunPublicInvokerBinding],
) -> list[str]:
    return sorted(
        {
            f"source={binding['source']}; role={binding['role']}; member={binding['member']}; condition=none"
            for binding in public_invokers
        }
    )


def _cloud_run_iam_target_state(
    iam_resource: NormalizedResource,
    workload: NormalizedResource,
    current_resources: Sequence[NormalizedResource],
) -> Literal["exact", "unrelated", "unknown"]:
    scope_may_match = _cloud_run_iam_scope_matches_workload(
        iam_resource,
        workload,
    )
    if gcp_facts(iam_resource).iam_scope_reference_state in {
        "unknown",
        "not_configured",
    }:
        return "unknown" if scope_may_match else "unrelated"

    target_reference = _known_string(resource_iam_target_reference(iam_resource))
    if target_reference is None:
        return "unknown" if scope_may_match else "unrelated"

    target_key = gcp_reference_key(
        target_reference,
        GCP_NETWORK_REFERENCE_SUFFIXES,
    )
    if target_key not in set(gcp_resource_references(workload)):
        return "unrelated"

    candidates = [
        candidate
        for candidate in current_resources
        if candidate.resource_type in GCP_CLOUD_RUN_RESOURCE_TYPES
        and target_key in set(gcp_resource_references(candidate))
        and _cloud_run_iam_scope_matches_workload(iam_resource, candidate)
    ]
    if len(candidates) != 1:
        return "unknown" if candidates else "unrelated"
    return "exact" if candidates[0].address == workload.address else "unrelated"


def _cloud_run_iam_scope_matches_workload(
    iam_resource: NormalizedResource,
    workload: NormalizedResource,
) -> bool:
    iam_facts = gcp_facts(iam_resource)
    workload_facts = gcp_facts(workload)
    iam_project = _normalize_project(iam_facts.project)
    workload_project = _normalize_project(workload_facts.project)
    if iam_project is not None and workload_project is not None and iam_project != workload_project:
        return False

    iam_region = _known_string(iam_facts.get(GcpResourceMetadata.REGION))
    workload_region = _known_string(workload_facts.get(GcpResourceMetadata.REGION))
    return not (
        iam_region is not None and workload_region is not None and iam_region.casefold() != workload_region.casefold()
    )


def _cloud_run_iam_management_mode(
    resource: NormalizedResource,
) -> _IamManagementMode:
    if resource.resource_type.endswith("_iam_policy"):
        return "authoritative_policy"
    if resource.resource_type.endswith("_iam_binding"):
        return "authoritative_role_binding"
    return "additive_member"


def _cloud_run_iam_manager_state(
    resource: NormalizedResource,
    management_mode: _IamManagementMode,
) -> Literal["configured", "unknown"]:
    facts = gcp_facts(resource)
    if management_mode == "authoritative_policy" and facts.iam_policy_data_state in {
        "unknown",
        "invalid",
        "not_configured",
    }:
        return "unknown"
    if any(
        binding.get("role_state") == "unknown" or binding.get("members_state") == "unknown"
        for binding in iam_bindings(resource)
    ):
        return "unknown"
    return "configured"


def _cloud_run_iam_manager_roles(
    resource: NormalizedResource,
) -> tuple[str, ...]:
    roles = {role for binding in iam_bindings(resource) if (role := _known_string(binding.get("role"))) is not None}
    configured_role = _known_string(gcp_facts(resource).get(GcpResourceMetadata.IAM_ROLE))
    if configured_role is not None:
        roles.add(configured_role)
    return tuple(sorted(roles))


def _cloud_run_iam_scope_is_ambiguous(
    managers: Sequence[_IamManager],
) -> bool:
    policy_sources = {resource.address for resource, mode, _roles in managers if mode == "authoritative_policy"}
    other_sources = {resource.address for resource, mode, _roles in managers if mode != "authoritative_policy"}
    return len(policy_sources) > 1 or bool(policy_sources and other_sources)


def _cloud_run_iam_ambiguous_roles(
    managers: Sequence[_IamManager],
) -> set[str]:
    ambiguous_roles: set[str] = set()
    roles = {role for _resource, _mode, manager_roles in managers for role in manager_roles}
    for role in roles:
        binding_sources = {
            resource.address
            for resource, mode, manager_roles in managers
            if mode == "authoritative_role_binding" and role in manager_roles
        }
        member_sources = {
            resource.address
            for resource, mode, manager_roles in managers
            if mode == "additive_member" and role in manager_roles
        }
        if len(binding_sources) > 1 or (binding_sources and member_sources):
            ambiguous_roles.add(role)
    return ambiguous_roles


def _normalize_project(value: object) -> str | None:
    text = _known_string(value)
    if text is None:
        return None
    if text.startswith("projects/"):
        return text.removeprefix("projects/").split("/", 1)[0] or None
    return text


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None
