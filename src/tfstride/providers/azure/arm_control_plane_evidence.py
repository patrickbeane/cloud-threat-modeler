from __future__ import annotations

from typing import Literal, TypedDict

AzureArmControlPlaneAuthorityState = Literal[
    "granted",
    "not_granted",
    "unknown",
    "unrelated",
]
AzureArmScopeType = Literal[
    "management_group",
    "subscription",
    "resource_group",
    "resource",
]
AzureArmRoleDefinitionConditionState = Literal[
    "not_configured",
    "configured",
    "unknown",
]
AzureArmDelegationConstraintKind = Literal[
    "none",
    "allowed_role_definition_ids",
    "unknown",
]


class AzureArmControlPlaneGrant(TypedDict):
    source_address: str
    principal_id: str | None
    principal_type: str | None
    principal_state: str
    assignment_scope_type: AzureArmScopeType
    assignment_scope: str | None
    assignment_scope_arm_id: str
    assignment_scope_state: Literal["resolved"]
    target_arm_id: str
    role_definition_name: str | None
    role_definition_id: str | None
    role_definition_address: str | None
    role_kind: str
    role_resolution_state: str
    role_actions: list[str]
    role_not_actions: list[str]
    requested_actions: list[str]
    matched_actions: list[str]
    excluded_actions: list[str]
    assignable_scope_compatibility_state: str
    assignment_condition: str | None
    assignment_condition_version: str | None
    assignment_condition_state: str
    role_definition_condition_state: AzureArmRoleDefinitionConditionState
    delegation_constraint_kind: AzureArmDelegationConstraintKind
    allowed_role_definition_ids: list[str]
    authorization_state: Literal["granted"]
    deny_assignments_evaluated: Literal[False]
    evaluation_basis: Literal["modeled_arm_control_plane_authority"]
