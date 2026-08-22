from __future__ import annotations

import unittest

from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _NAMESPACE_ID,
    _QUEUE_ID,
    _SYSTEM_PRINCIPAL_ID,
    _TOPIC_ID,
    _USER_PRINCIPAL_ID,
    _entity,
    _namespace,
    _resource,
    _subscription,
    _user_assigned_identity,
    _web_app,
)
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_decoration_stages import (
    default_azure_decoration_stages,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_DELETE_NAMESPACE = "Microsoft.ServiceBus/namespaces/delete"
_DELETE_QUEUE = "Microsoft.ServiceBus/namespaces/queues/delete"
_DELETE_TOPIC = "Microsoft.ServiceBus/namespaces/topics/delete"
_DELETE_SUBSCRIPTION = "Microsoft.ServiceBus/namespaces/topics/subscriptions/delete"
_CONTROL_ROLE_ID = (
    "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/messaging-topology-operator"
)
_WORKLOAD_ADDRESS = "azurerm_linux_web_app.orders"
_NAMESPACE_ADDRESS = "azurerm_servicebus_namespace.orders"
_QUEUE_ADDRESS = "azurerm_servicebus_queue.orders"
_TOPIC_ADDRESS = "azurerm_servicebus_topic.orders"
_SUBSCRIPTION_ADDRESS = "azurerm_servicebus_subscription.orders"
_ROLE_ADDRESS = "azurerm_role_definition.messaging_topology"


def _control_role(
    *,
    actions: list[str],
    not_actions: list[str] | None = None,
    data_actions: list[str] | None = None,
    assignable_scopes: list[str] | None = None,
) -> TerraformResource:
    return _resource(
        AzureResourceType.ROLE_DEFINITION,
        {
            "id": _CONTROL_ROLE_ID,
            "name": "Messaging Topology Operator",
            "scope": "/subscriptions/sub-0001",
            "assignable_scopes": assignable_scopes or ["/subscriptions/sub-0001"],
            "permissions": [
                {
                    "actions": actions,
                    "not_actions": not_actions or [],
                    "data_actions": data_actions or [],
                    "not_data_actions": [],
                }
            ],
        },
        name="messaging_topology",
    )


def _control_assignment(
    *,
    scope: object = "azurerm_servicebus_namespace.orders.id",
    principal_id: object = _SYSTEM_PRINCIPAL_ID,
    condition: object | None = None,
    name: str = "messaging_topology",
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "scope": scope,
        "role_definition_id": _CONTROL_ROLE_ID,
        "principal_id": principal_id,
        "principal_type": "ServicePrincipal",
    }
    if condition is not None:
        values["condition"] = condition
        values["condition_version"] = "2.0"
    return _resource(
        AzureResourceType.ROLE_ASSIGNMENT,
        values,
        name=name,
        unknown_values=unknown_values,
    )


def _contributor_assignment() -> TerraformResource:
    return _resource(
        AzureResourceType.ROLE_ASSIGNMENT,
        {
            "scope": "azurerm_servicebus_queue.orders.id",
            "role_definition_name": "Contributor",
            "principal_id": _SYSTEM_PRINCIPAL_ID,
            "principal_type": "ServicePrincipal",
        },
        name="queue_contributor",
    )


def _management_lock(
    *,
    scope: object,
    lock_level: object = "CanNotDelete",
    name: str = "topology_lock",
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return _resource(
        AzureResourceType.MANAGEMENT_LOCK,
        {
            "name": name,
            "scope": scope,
            "lock_level": lock_level,
            "notes": "Protect Service Bus topology",
        },
        name=name,
        unknown_values=unknown_values,
    )


def _workload(*, public: bool = True) -> TerraformResource:
    workload = _web_app()
    workload.values["public_network_access_enabled"] = public
    return workload


def _workload_facts(resources: list[TerraformResource]):
    inventory = AzureNormalizer().normalize(resources)
    workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
    assert workload is not None
    return azure_facts(workload)


class AzureAppServiceServiceBusTopologyDestructionPathTests(unittest.TestCase):
    def test_management_lock_normalization_preserves_plan_local_evidence(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _management_lock(
                    scope="azurerm_servicebus_namespace.orders.id",
                    lock_level="CanNotDelete",
                )
            ]
        )
        lock = inventory.get_by_address("azurerm_management_lock.topology_lock")
        assert lock is not None

        facts = azure_facts(lock)
        self.assertEqual(
            facts.management_lock_scope,
            "azurerm_servicebus_namespace.orders.id",
        )
        self.assertEqual(facts.management_lock_level, "CanNotDelete")
        self.assertEqual(facts.management_lock_uncertainties, [])

    def test_namespace_scope_fans_out_only_to_exact_modeled_topology(self) -> None:
        facts = _workload_facts(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                _subscription(),
                _workload(),
                _control_role(
                    actions=[
                        _DELETE_NAMESPACE,
                        _DELETE_QUEUE,
                        _DELETE_TOPIC,
                        _DELETE_SUBSCRIPTION,
                    ]
                ),
                _control_assignment(),
            ]
        )

        paths = {
            path["service_bus_resource_kind"]: path for path in facts.app_service_service_bus_topology_destruction_paths
        }
        self.assertEqual(
            set(paths),
            {"namespace", "queue", "topic", "subscription"},
        )
        self.assertEqual(
            {kind: path["operation"] for kind, path in paths.items()},
            {
                "namespace": _DELETE_NAMESPACE,
                "queue": _DELETE_QUEUE,
                "topic": _DELETE_TOPIC,
                "subscription": _DELETE_SUBSCRIPTION,
            },
        )
        self.assertEqual(
            paths["namespace"]["target_model_evidence_addresses"],
            [_NAMESPACE_ADDRESS],
        )
        self.assertEqual(
            paths["queue"]["target_model_evidence_addresses"],
            [_NAMESPACE_ADDRESS, _QUEUE_ADDRESS],
        )
        self.assertEqual(
            paths["topic"]["target_model_evidence_addresses"],
            [_NAMESPACE_ADDRESS, _TOPIC_ADDRESS],
        )
        self.assertEqual(
            paths["subscription"]["target_model_evidence_addresses"],
            [_NAMESPACE_ADDRESS, _TOPIC_ADDRESS, _SUBSCRIPTION_ADDRESS],
        )

        for path in paths.values():
            grant = path["authorization_grant"]
            self.assertEqual(grant["assignment_scope_arm_id"], _NAMESPACE_ID)
            self.assertEqual(grant["assignment_scope_type"], "resource")
            self.assertEqual(grant["target_arm_id"], path["service_bus_resource_id"])
            self.assertEqual(grant["matched_actions"], [path["operation"]])
            self.assertEqual(
                grant["role_evidence"],
                {
                    "role_kind": "custom",
                    "role_resolution_state": "resolved",
                    "role_definition_address": _ROLE_ADDRESS,
                    "assignable_scope_compatibility_state": "resolved",
                },
            )
            self.assertEqual(
                set(path["authorization_source_addresses"]),
                {
                    "azurerm_role_assignment.messaging_topology",
                    _ROLE_ADDRESS,
                },
            )
            self.assertEqual(
                path["management_lock_evidence"],
                {
                    "lock_evidence_scope": "plan_local_service_bus_ancestry",
                    "modeled_management_lock_state": "not_observed",
                    "applicable_lock_addresses": [],
                    "applicable_lock_levels": [],
                    "external_management_locks_evaluated": False,
                    "deletion_compatibility_state": "compatible",
                    "uncertainties": [],
                },
            )
            self.assertFalse(path["outcome_evidence"]["successful_deletion_observed"])
            self.assertEqual(
                path["outcome_evidence"]["recovery_state"],
                "not_established_by_modeled_azure_messaging_topology_evidence",
            )

    def test_exact_queue_scope_preserves_built_in_role_evidence(self) -> None:
        facts = _workload_facts(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                _workload(),
                _contributor_assignment(),
            ]
        )

        self.assertEqual(
            [path["operation"] for path in facts.app_service_service_bus_topology_destruction_paths],
            [_DELETE_QUEUE],
        )
        path = facts.app_service_service_bus_topology_destruction_paths[0]
        self.assertEqual(path["target_scope"], "exact_service_bus_queue")
        self.assertEqual(
            path["authorization_grant"]["role_evidence"],
            {
                "role_kind": "built_in",
                "role_resolution_state": "modeled_subset",
                "role_definition_address": None,
                "assignable_scope_compatibility_state": "not_applicable",
            },
        )
        self.assertEqual(
            path["authorization_source_addresses"],
            ["azurerm_role_assignment.queue_contributor"],
        )

    def test_system_and_user_assigned_runtime_identities_remain_distinct(self) -> None:
        workload = _workload()
        identity = workload.values["identity"]
        assert isinstance(identity, list)
        identity_record = identity[0]
        assert isinstance(identity_record, dict)
        identity_record["type"] = "SystemAssigned, UserAssigned"
        identity_record["identity_ids"] = ["azurerm_user_assigned_identity.orders_runtime.id"]
        facts = _workload_facts(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                _user_assigned_identity(),
                workload,
                _control_role(actions=[_DELETE_QUEUE]),
                _control_assignment(
                    scope="azurerm_servicebus_queue.orders.id",
                    name="system_topology",
                ),
                _control_assignment(
                    scope="azurerm_servicebus_queue.orders.id",
                    principal_id=_USER_PRINCIPAL_ID,
                    name="user_topology",
                ),
            ]
        )

        self.assertEqual(
            {
                (
                    path["identity_address"],
                    path["identity_kind"],
                    path["principal_id"],
                )
                for path in facts.app_service_service_bus_topology_destruction_paths
            },
            {
                (
                    _WORKLOAD_ADDRESS,
                    "system_assigned",
                    _SYSTEM_PRINCIPAL_ID,
                ),
                (
                    "azurerm_user_assigned_identity.orders_runtime",
                    "user_assigned",
                    _USER_PRINCIPAL_ID,
                ),
            },
        )

    def test_conditional_or_incompatible_authority_fails_closed(self) -> None:
        cases = {
            "condition": (
                _control_role(actions=[_DELETE_QUEUE]),
                _control_assignment(
                    scope="azurerm_servicebus_queue.orders.id",
                    condition="@Resource[Microsoft.ServiceBus/namespaces/queues:Name] StringEquals 'orders'",
                ),
            ),
            "unknown condition": (
                _control_role(actions=[_DELETE_QUEUE]),
                _control_assignment(
                    scope="azurerm_servicebus_queue.orders.id",
                    unknown_values={"condition": True},
                ),
            ),
            "unknown condition version": (
                _control_role(actions=[_DELETE_QUEUE]),
                _control_assignment(
                    scope="azurerm_servicebus_queue.orders.id",
                    unknown_values={"condition_version": True},
                ),
            ),
            "outside assignable scope": (
                _control_role(
                    actions=[_DELETE_QUEUE],
                    assignable_scopes=["/subscriptions/other-subscription"],
                ),
                _control_assignment(
                    scope="azurerm_servicebus_queue.orders.id",
                ),
            ),
        }

        for case, (role, assignment) in cases.items():
            with self.subTest(case=case):
                facts = _workload_facts(
                    [
                        _namespace(),
                        _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                        _workload(),
                        role,
                        assignment,
                    ]
                )
                self.assertEqual(
                    facts.app_service_service_bus_topology_destruction_paths,
                    [],
                )
                self.assertTrue(facts.app_service_service_bus_topology_destruction_path_uncertainties)

    def test_exclusions_and_data_actions_do_not_become_control_plane_deletion(self) -> None:
        cases = {
            "not action": _control_role(
                actions=["Microsoft.ServiceBus/namespaces/*"],
                not_actions=[_DELETE_QUEUE],
            ),
            "data action": _control_role(
                actions=[],
                data_actions=[_DELETE_QUEUE],
            ),
        }

        for case, role in cases.items():
            with self.subTest(case=case):
                facts = _workload_facts(
                    [
                        _namespace(),
                        _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                        _workload(),
                        role,
                        _control_assignment(scope="azurerm_servicebus_queue.orders.id"),
                    ]
                )
                self.assertEqual(
                    facts.app_service_service_bus_topology_destruction_paths,
                    [],
                )

    def test_namespace_lock_blocks_namespace_and_all_modeled_descendants(self) -> None:
        facts = _workload_facts(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                _subscription(),
                _workload(),
                _control_role(
                    actions=[
                        _DELETE_NAMESPACE,
                        _DELETE_QUEUE,
                        _DELETE_TOPIC,
                        _DELETE_SUBSCRIPTION,
                    ]
                ),
                _control_assignment(),
                _management_lock(
                    scope="azurerm_servicebus_namespace.orders.id",
                ),
            ]
        )

        self.assertEqual(
            facts.app_service_service_bus_topology_destruction_paths,
            [],
        )
        self.assertEqual(
            facts.app_service_service_bus_topology_destruction_path_uncertainties,
            [],
        )

    def test_resource_group_read_only_lock_blocks_service_bus_topology(self) -> None:
        facts = _workload_facts(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                _workload(),
                _control_role(actions=[_DELETE_NAMESPACE, _DELETE_QUEUE]),
                _control_assignment(),
                _management_lock(
                    scope="/subscriptions/sub-0001/resourceGroups/app",
                    lock_level="ReadOnly",
                ),
            ]
        )

        self.assertEqual(
            facts.app_service_service_bus_topology_destruction_paths,
            [],
        )

    def test_queue_lock_does_not_block_sibling_topic(self) -> None:
        facts = _workload_facts(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                _workload(),
                _control_role(actions=[_DELETE_QUEUE, _DELETE_TOPIC]),
                _control_assignment(),
                _management_lock(
                    scope="azurerm_servicebus_queue.orders.id",
                ),
            ]
        )

        self.assertEqual(
            [
                (path["service_bus_resource_kind"], path["operation"])
                for path in facts.app_service_service_bus_topology_destruction_paths
            ],
            [("topic", _DELETE_TOPIC)],
        )

    def test_topic_lock_blocks_topic_and_subscription_descendant(self) -> None:
        facts = _workload_facts(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                _subscription(),
                _workload(),
                _control_role(actions=[_DELETE_TOPIC, _DELETE_SUBSCRIPTION]),
                _control_assignment(),
                _management_lock(
                    scope="azurerm_servicebus_topic.orders.id",
                ),
            ]
        )

        self.assertEqual(
            facts.app_service_service_bus_topology_destruction_paths,
            [],
        )

    def test_unrelated_namespace_lock_does_not_suppress_target(self) -> None:
        audit_namespace_id = (
            "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.ServiceBus/namespaces/audit-events"
        )
        audit_namespace = _resource(
            AzureResourceType.SERVICE_BUS_NAMESPACE,
            {
                "id": audit_namespace_id,
                "name": "audit-events",
                "sku": "Premium",
            },
            name="audit",
        )
        facts = _workload_facts(
            [
                _namespace(),
                audit_namespace,
                _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                _workload(),
                _control_role(actions=[_DELETE_QUEUE]),
                _control_assignment(),
                _management_lock(
                    scope="azurerm_servicebus_namespace.audit.id",
                ),
            ]
        )

        self.assertEqual(
            [path["operation"] for path in facts.app_service_service_bus_topology_destruction_paths],
            [_DELETE_QUEUE],
        )

    def test_unknown_potentially_applicable_lock_scope_or_level_fails_closed(self) -> None:
        cases = {
            "scope": _management_lock(
                scope=None,
                unknown_values={"scope": True},
            ),
            "level": _management_lock(
                scope="azurerm_servicebus_namespace.orders.id",
                lock_level=None,
                unknown_values={"lock_level": True},
            ),
        }

        for field, lock in cases.items():
            with self.subTest(field=field):
                facts = _workload_facts(
                    [
                        _namespace(),
                        _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                        _workload(),
                        _control_role(actions=[_DELETE_QUEUE]),
                        _control_assignment(),
                        lock,
                    ]
                )
                self.assertEqual(
                    facts.app_service_service_bus_topology_destruction_paths,
                    [],
                )
                self.assertTrue(
                    any(
                        "azurerm_management_lock.topology_lock" in uncertainty and field in uncertainty
                        for uncertainty in facts.app_service_service_bus_topology_destruction_path_uncertainties
                    )
                )

    def test_unresolved_target_identity_fails_closed_with_uncertainty(self) -> None:
        queue = _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID)
        queue.values["id"] = None
        queue.unknown_values["id"] = True
        facts = _workload_facts(
            [
                _namespace(),
                queue,
                _workload(),
                _control_role(actions=[_DELETE_QUEUE]),
                _control_assignment(),
            ]
        )

        self.assertEqual(
            facts.app_service_service_bus_topology_destruction_paths,
            [],
        )
        self.assertTrue(
            any(
                _QUEUE_ADDRESS in uncertainty and "identity" in uncertainty
                for uncertainty in facts.app_service_service_bus_topology_destruction_path_uncertainties
            )
        )

    def test_private_workload_keeps_paths_and_unmodeled_children_are_not_invented(
        self,
    ) -> None:
        private_facts = _workload_facts(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                _workload(public=False),
                _control_role(actions=[_DELETE_QUEUE]),
                _control_assignment(),
            ]
        )
        self.assertEqual(
            [path["operation"] for path in private_facts.app_service_service_bus_topology_destruction_paths],
            [_DELETE_QUEUE],
        )

        namespace_only_facts = _workload_facts(
            [
                _namespace(),
                _workload(),
                _control_role(actions=[_DELETE_QUEUE]),
                _control_assignment(),
            ]
        )
        self.assertEqual(
            namespace_only_facts.app_service_service_bus_topology_destruction_paths,
            [],
        )

    def test_stage_runs_after_service_bus_relationships_and_identity_decoration(
        self,
    ) -> None:
        names = [stage.name for stage in default_azure_decoration_stages()]
        topology = names.index("model_app_service_service_bus_topology_destruction_paths")

        self.assertGreater(topology, names.index("decorate_service_bus_relationships"))
        self.assertGreater(
            topology,
            names.index("decorate_managed_identity_role_assignments"),
        )
        self.assertGreater(
            topology,
            names.index("model_app_service_service_bus_message_removal_paths"),
        )


if __name__ == "__main__":
    unittest.main()
