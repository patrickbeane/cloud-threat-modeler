from __future__ import annotations

from typing import Literal, TypedDict

from tfstride.providers.azure.key_vault_evidence import (
    AzureKeyVaultRuntimeIdentityKind,
)

AzureServiceBusMessageRemovalOperation = Literal["microsoft.servicebus/namespaces/messages/receive/action"]
AzureServiceBusMessageRemovalOperationClass = Literal["destructive_message_receive"]
AzureServiceBusMessageRemovalManagementEffect = Literal["disruption"]
AzureServiceBusMessageRemovalTargetGranularity = Literal[
    "namespace_message_namespace",
    "queue_message_namespace",
    "subscription_message_namespace",
]
AzureServiceBusMessageRemovalScopeType = Literal[
    "namespace",
    "queue",
    "subscription",
]


class AzureServiceBusMessageRemovalDeliveryEvidence(TypedDict):
    delivery_evidence_scope: Literal["service_bus_message_delivery_posture"]
    default_message_time_to_live: str | None
    lock_duration: str | None
    max_delivery_count: int | None
    dead_lettering_on_message_expiration: bool | None
    removed_message_recovery_state: Literal["not_established_by_modeled_service_bus_delivery_controls"]
    uncertainties: list[str]


class AzureAppServiceServiceBusMessageRemovalPathCommon(TypedDict):
    workload_address: str
    workload_type: str
    identity_address: str
    identity_kind: AzureKeyVaultRuntimeIdentityKind
    principal_id: str
    credential_context: Literal["workload_runtime"]
    service_bus_resource_address: str
    service_bus_resource_type: str
    service_bus_resource_id: str
    service_bus_namespace_address: str
    service_bus_namespace_id: str
    operation: Literal["microsoft.servicebus/namespaces/messages/receive/action"]
    operation_class: Literal["destructive_message_receive"]
    management_effect: Literal["disruption"]
    target_model_evidence_addresses: list[str]
    receive_and_delete_capability: Literal[True]
    peek_lock_complete_capability: Literal[True]
    runtime_receive_mode_selection: Literal["not_plan_visible"]
    complete_lock_token_source: Literal["runtime_peek_lock_receive"]
    complete_lock_token_value: None
    role_assignment_address: str
    role_definition_name: str
    role_definition_id: str | None
    role_definition_address: str | None
    role_kind: str
    grant_basis: str
    evaluation_basis: Literal["modeled_rbac_assignment"]
    assignment_scope: str
    assignment_scope_kind: str
    authorization_source_addresses: list[str]
    custom_role_data_actions: list[str]
    custom_role_not_data_actions: list[str]
    matched_data_actions: list[Literal["microsoft.servicebus/namespaces/messages/receive/action"]]
    excluded_data_actions: list[str]
    condition: None
    condition_state: Literal["not_configured"]
    authorization_state: Literal["granted"]
    policy_complete: Literal[True]
    lifecycle_compatibility_state: Literal["not_applicable"]
    delivery_evidence: AzureServiceBusMessageRemovalDeliveryEvidence
    posture_uncertainties: list[str]


class AzureAppServiceServiceBusNamespaceMessageRemovalPath(
    AzureAppServiceServiceBusMessageRemovalPathCommon,
):
    scope_type: Literal["namespace"]
    target_granularity: Literal["namespace_message_namespace"]
    target_scope: Literal["exact_service_bus_namespace_message_namespace"]
    service_bus_entity_kind: None
    queue_address: None
    topic_address: None
    subscription_address: None


class AzureAppServiceServiceBusQueueMessageRemovalPath(
    AzureAppServiceServiceBusMessageRemovalPathCommon,
):
    scope_type: Literal["queue"]
    target_granularity: Literal["queue_message_namespace"]
    target_scope: Literal["exact_service_bus_queue_message_namespace"]
    service_bus_entity_kind: Literal["queue"]
    queue_address: str
    topic_address: None
    subscription_address: None


class AzureAppServiceServiceBusSubscriptionMessageRemovalPath(
    AzureAppServiceServiceBusMessageRemovalPathCommon,
):
    scope_type: Literal["subscription"]
    target_granularity: Literal["subscription_message_namespace"]
    target_scope: Literal["exact_service_bus_subscription_message_namespace"]
    service_bus_entity_kind: Literal["subscription"]
    queue_address: None
    topic_address: str
    subscription_address: str


AzureAppServiceServiceBusMessageRemovalPath = (
    AzureAppServiceServiceBusNamespaceMessageRemovalPath
    | AzureAppServiceServiceBusQueueMessageRemovalPath
    | AzureAppServiceServiceBusSubscriptionMessageRemovalPath
)
AzureAppServiceServiceBusMessageRemovalEvidence = AzureAppServiceServiceBusMessageRemovalPath
