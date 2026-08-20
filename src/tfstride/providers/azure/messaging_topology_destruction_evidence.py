from __future__ import annotations

from typing import Literal, Never, TypedDict

from tfstride.providers.azure.arm_control_plane_evidence import (
    AzureArmScopeType,
)
from tfstride.providers.azure.key_vault_evidence import (
    AzureKeyVaultRuntimeIdentityKind,
)

AzureServiceBusTopologyDestructionOperation = Literal[
    "Microsoft.ServiceBus/namespaces/delete",
    "Microsoft.ServiceBus/namespaces/queues/delete",
    "Microsoft.ServiceBus/namespaces/topics/delete",
    "Microsoft.ServiceBus/namespaces/topics/subscriptions/delete",
]
AzureServiceBusTopologyDestructionOperationClass = Literal[
    "namespace_deletion",
    "queue_deletion",
    "topic_deletion",
    "subscription_deletion",
]
AzureServiceBusTopologyDestructionInternalOperation = Literal[
    "delete_namespace",
    "delete_queue",
    "delete_topic",
    "delete_subscription",
]
AzureServiceBusTopologyDestructionTargetGranularity = Literal[
    "service_bus_namespace_topology",
    "queue_topology",
    "topic_topology",
    "subscription_topology",
]


class AzureServiceBusTopologyBuiltInRoleEvidence(TypedDict):
    role_kind: Literal["built_in"]
    role_resolution_state: Literal["modeled_subset"]
    role_definition_address: None
    assignable_scope_compatibility_state: Literal["not_applicable"]


class AzureServiceBusTopologyCustomRoleEvidence(TypedDict):
    role_kind: Literal["custom"]
    role_resolution_state: Literal["resolved"]
    role_definition_address: str
    assignable_scope_compatibility_state: Literal["resolved"]


AzureServiceBusTopologyRoleEvidence = (
    AzureServiceBusTopologyBuiltInRoleEvidence | AzureServiceBusTopologyCustomRoleEvidence
)


class AzureServiceBusTopologyDestructionAuthorizationGrantCommon(TypedDict):
    source_address: str
    principal_id: str
    principal_type: str | None
    principal_state: Literal["resolved"]
    assignment_scope_type: AzureArmScopeType
    assignment_scope: str | None
    assignment_scope_arm_id: str
    assignment_scope_state: Literal["resolved"]
    target_arm_id: str
    role_definition_name: str | None
    role_definition_id: str | None
    role_evidence: AzureServiceBusTopologyRoleEvidence
    role_actions: list[str]
    role_not_actions: list[str]
    excluded_actions: list[Never]
    assignment_condition: None
    assignment_condition_version: None
    assignment_condition_state: Literal["not_configured"]
    role_definition_condition_state: Literal["not_configured"]
    delegation_constraint_kind: Literal["none"]
    allowed_role_definition_ids: list[Never]
    authorization_state: Literal["granted"]
    deny_assignments_evaluated: Literal[False]
    evaluation_basis: Literal["modeled_arm_control_plane_authority"]


class AzureServiceBusNamespaceDeletionAuthorizationGrant(
    AzureServiceBusTopologyDestructionAuthorizationGrantCommon,
):
    requested_actions: list[Literal["Microsoft.ServiceBus/namespaces/delete"]]
    matched_actions: list[Literal["Microsoft.ServiceBus/namespaces/delete"]]


class AzureServiceBusQueueDeletionAuthorizationGrant(
    AzureServiceBusTopologyDestructionAuthorizationGrantCommon,
):
    requested_actions: list[Literal["Microsoft.ServiceBus/namespaces/queues/delete"]]
    matched_actions: list[Literal["Microsoft.ServiceBus/namespaces/queues/delete"]]


class AzureServiceBusTopicDeletionAuthorizationGrant(
    AzureServiceBusTopologyDestructionAuthorizationGrantCommon,
):
    requested_actions: list[Literal["Microsoft.ServiceBus/namespaces/topics/delete"]]
    matched_actions: list[Literal["Microsoft.ServiceBus/namespaces/topics/delete"]]


class AzureServiceBusSubscriptionDeletionAuthorizationGrant(
    AzureServiceBusTopologyDestructionAuthorizationGrantCommon,
):
    requested_actions: list[Literal["Microsoft.ServiceBus/namespaces/topics/subscriptions/delete"]]
    matched_actions: list[Literal["Microsoft.ServiceBus/namespaces/topics/subscriptions/delete"]]


AzureServiceBusTopologyDestructionAuthorizationGrant = (
    AzureServiceBusNamespaceDeletionAuthorizationGrant
    | AzureServiceBusQueueDeletionAuthorizationGrant
    | AzureServiceBusTopicDeletionAuthorizationGrant
    | AzureServiceBusSubscriptionDeletionAuthorizationGrant
)


class AzureServiceBusTopologyDestructionLockEvidence(TypedDict):
    lock_evidence_scope: Literal["plan_local_service_bus_ancestry"]
    modeled_management_lock_state: Literal["not_observed"]
    applicable_lock_addresses: list[Never]
    applicable_lock_levels: list[Never]
    external_management_locks_evaluated: Literal[False]
    deletion_compatibility_state: Literal["compatible"]
    uncertainties: list[str]


class AzureServiceBusTopologyDestructionOutcomeEvidence(TypedDict):
    outcome_evidence_scope: Literal["plan_local_service_bus_topology_deletion_authority"]
    successful_deletion_observed: Literal[False]
    recovery_state: Literal["not_established_by_modeled_azure_messaging_topology_evidence"]
    out_of_plan_topology_evaluated: Literal[False]
    uncertainties: list[str]


class AzureAppServiceServiceBusTopologyDestructionPathCommon(TypedDict):
    workload_address: str
    workload_type: str
    identity_address: str
    identity_kind: AzureKeyVaultRuntimeIdentityKind
    principal_id: str
    credential_context: Literal["workload_runtime"]
    service_bus_namespace_address: str
    service_bus_namespace_id: str
    service_bus_resource_address: str
    service_bus_resource_type: str
    service_bus_resource_id: str
    target_model_evidence_addresses: list[str]
    management_effect: Literal["disruption"]
    role_assignment_address: str
    authorization_source_addresses: list[str]
    authorization_state: Literal["granted"]
    modeled_allow_evidence_complete: Literal[True]
    condition: None
    condition_state: Literal["not_configured"]
    lifecycle_compatibility_state: Literal["compatible"]
    management_lock_evidence: AzureServiceBusTopologyDestructionLockEvidence
    outcome_evidence: AzureServiceBusTopologyDestructionOutcomeEvidence
    posture_uncertainties: list[str]


class AzureAppServiceServiceBusNamespaceDeletionPath(
    AzureAppServiceServiceBusTopologyDestructionPathCommon,
):
    service_bus_resource_kind: Literal["namespace"]
    operation: Literal["Microsoft.ServiceBus/namespaces/delete"]
    operation_class: Literal["namespace_deletion"]
    internal_operation: Literal["delete_namespace"]
    target_granularity: Literal["service_bus_namespace_topology"]
    target_scope: Literal["exact_service_bus_namespace"]
    queue_address: None
    queue_id: None
    topic_address: None
    topic_id: None
    subscription_address: None
    subscription_id: None
    authorization_grant: AzureServiceBusNamespaceDeletionAuthorizationGrant


class AzureAppServiceServiceBusQueueDeletionPath(
    AzureAppServiceServiceBusTopologyDestructionPathCommon,
):
    service_bus_resource_kind: Literal["queue"]
    operation: Literal["Microsoft.ServiceBus/namespaces/queues/delete"]
    operation_class: Literal["queue_deletion"]
    internal_operation: Literal["delete_queue"]
    target_granularity: Literal["queue_topology"]
    target_scope: Literal["exact_service_bus_queue"]
    queue_address: str
    queue_id: str
    topic_address: None
    topic_id: None
    subscription_address: None
    subscription_id: None
    authorization_grant: AzureServiceBusQueueDeletionAuthorizationGrant


class AzureAppServiceServiceBusTopicDeletionPath(
    AzureAppServiceServiceBusTopologyDestructionPathCommon,
):
    service_bus_resource_kind: Literal["topic"]
    operation: Literal["Microsoft.ServiceBus/namespaces/topics/delete"]
    operation_class: Literal["topic_deletion"]
    internal_operation: Literal["delete_topic"]
    target_granularity: Literal["topic_topology"]
    target_scope: Literal["exact_service_bus_topic"]
    queue_address: None
    queue_id: None
    topic_address: str
    topic_id: str
    subscription_address: None
    subscription_id: None
    authorization_grant: AzureServiceBusTopicDeletionAuthorizationGrant


class AzureAppServiceServiceBusSubscriptionDeletionPath(
    AzureAppServiceServiceBusTopologyDestructionPathCommon,
):
    service_bus_resource_kind: Literal["subscription"]
    operation: Literal["Microsoft.ServiceBus/namespaces/topics/subscriptions/delete"]
    operation_class: Literal["subscription_deletion"]
    internal_operation: Literal["delete_subscription"]
    target_granularity: Literal["subscription_topology"]
    target_scope: Literal["exact_service_bus_subscription"]
    queue_address: None
    queue_id: None
    topic_address: str
    topic_id: str
    subscription_address: str
    subscription_id: str
    authorization_grant: AzureServiceBusSubscriptionDeletionAuthorizationGrant


AzureAppServiceServiceBusTopologyDestructionPath = (
    AzureAppServiceServiceBusNamespaceDeletionPath
    | AzureAppServiceServiceBusQueueDeletionPath
    | AzureAppServiceServiceBusTopicDeletionPath
    | AzureAppServiceServiceBusSubscriptionDeletionPath
)
AzureAppServiceServiceBusTopologyDestructionEvidence = AzureAppServiceServiceBusTopologyDestructionPath
