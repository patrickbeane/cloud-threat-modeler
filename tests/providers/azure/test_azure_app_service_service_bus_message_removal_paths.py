from __future__ import annotations

import unittest

from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _CUSTOM_ROLE_ID,
    _NAMESPACE_ID,
    _QUEUE_ID,
    _SYSTEM_PRINCIPAL_ID,
    _TOPIC_ID,
    _USER_PRINCIPAL_ID,
    _custom_role,
    _entity,
    _function_app,
    _namespace,
    _role_assignment,
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

_RECEIVE = "microsoft.servicebus/namespaces/messages/receive/action"
_RECEIVER_ROLE_ID = (
    "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0"
)
_SENDER_ROLE_ID = (
    "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/69a216fc-b8fb-44d8-bc22-1f3c2cd27a39"
)


def _receiver_assignment(
    *,
    scope: object = "azurerm_servicebus_namespace.orders.id",
    principal_id: object = _SYSTEM_PRINCIPAL_ID,
    condition: object | None = None,
) -> TerraformResource:
    return _role_assignment(
        principal_id=principal_id,
        scope=scope,
        role_name="Azure Service Bus Data Receiver",
        role_definition_id=_RECEIVER_ROLE_ID,
        condition=condition,
    )


def _queue(
    *,
    unknown_delivery: bool = False,
    status: object | None = None,
    unknown_status: bool = False,
    unknown_entity_id: bool = False,
    forward_to: object | None = None,
    unknown_forward_to: bool = False,
) -> TerraformResource:
    queue = _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID)
    queue.values.update(
        {
            "default_message_ttl": "P14D",
            "lock_duration": "PT2M",
            "max_delivery_count": 8,
            "dead_lettering_on_message_expiration": True,
        }
    )
    if status is not None:
        queue.values["status"] = status
    if unknown_delivery:
        queue.unknown_values.update(
            {
                "default_message_ttl": True,
                "lock_duration": True,
                "max_delivery_count": True,
                "dead_lettering_on_message_expiration": True,
            }
        )
    if unknown_status:
        queue.unknown_values["status"] = True
    if forward_to is not None:
        queue.values["forward_to"] = forward_to
    if unknown_forward_to:
        queue.unknown_values["forward_to"] = True
    if unknown_entity_id:
        queue.values["id"] = None
        queue.unknown_values["id"] = True
    return queue


def _subscription_with_delivery(
    *,
    status: object | None = None,
    unknown_status: bool = False,
    unknown_topic: bool = False,
    forward_to: object | None = None,
    unknown_forward_to: bool = False,
) -> TerraformResource:
    subscription = _subscription()
    subscription.values.update(
        {
            "default_message_ttl": "P7D",
            "lock_duration": "PT1M",
            "max_delivery_count": 5,
            "dead_lettering_on_message_expiration": False,
        }
    )
    if status is not None:
        subscription.values["status"] = status
    if unknown_status:
        subscription.unknown_values["status"] = True
    if forward_to is not None:
        subscription.values["forward_to"] = forward_to
    if unknown_forward_to:
        subscription.unknown_values["forward_to"] = True
    if unknown_topic:
        subscription.values["topic_id"] = None
        subscription.unknown_values["topic_id"] = True
    return subscription


def _custom_role_with_assignable_scopes(
    assignable_scopes: list[str],
    *,
    unknown_assignable_scopes: bool = False,
) -> TerraformResource:
    role = _custom_role(data_actions=[_RECEIVE])
    role.values["assignable_scopes"] = assignable_scopes
    if unknown_assignable_scopes:
        role.unknown_values["assignable_scopes"] = True
    return role


def _custom_receiver_assignment(
    *,
    scope: object,
) -> TerraformResource:
    return _role_assignment(
        scope=scope,
        role_name=None,
        role_definition_id=("azurerm_role_definition.service_bus_operator.role_definition_resource_id"),
    )


def _workload_facts(
    resources: list[TerraformResource],
    *,
    address: str = "azurerm_linux_web_app.orders",
):
    inventory = AzureNormalizer().normalize(resources)
    workload = inventory.get_by_address(address)
    assert workload is not None
    return azure_facts(workload)


class AzureAppServiceServiceBusMessageRemovalPathTests(unittest.TestCase):
    def test_namespace_assignment_fans_out_to_exact_consumable_descendants(
        self,
    ) -> None:
        facts = _workload_facts(
            [
                _namespace(),
                _queue(),
                _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                _subscription_with_delivery(),
                _web_app(),
                _receiver_assignment(),
            ]
        )

        paths = facts.app_service_service_bus_message_removal_paths
        self.assertEqual(len(paths), 2)
        paths_by_type = {path["service_bus_resource_type"]: path for path in paths}
        self.assertEqual(
            set(paths_by_type),
            {
                AzureResourceType.SERVICE_BUS_QUEUE,
                AzureResourceType.SERVICE_BUS_SUBSCRIPTION,
            },
        )
        self.assertNotIn(
            "azurerm_servicebus_namespace.orders",
            {path["service_bus_resource_address"] for path in paths},
        )
        for path in paths:
            self.assertEqual(
                path["assignment_scope"],
                "azurerm_servicebus_namespace.orders.id",
            )
            self.assertEqual(path["assignment_scope_kind"], "namespace")
            self.assertEqual(
                path["service_bus_namespace_address"],
                "azurerm_servicebus_namespace.orders",
            )
            self.assertEqual(path["service_bus_namespace_id"], _NAMESPACE_ID)
            self.assertEqual(
                path["service_bus_auto_forwarding_state"],
                "not_configured",
            )
            self.assertIsNone(path["service_bus_forward_to"])
            self.assertEqual(path["matched_data_actions"], [_RECEIVE])
            self.assertEqual(
                path["target_model_evidence_addresses"][0],
                "azurerm_servicebus_namespace.orders",
            )

        queue_path = paths_by_type[AzureResourceType.SERVICE_BUS_QUEUE]
        self.assertEqual(
            queue_path["target_model_evidence_addresses"],
            [
                "azurerm_servicebus_namespace.orders",
                "azurerm_servicebus_queue.orders",
            ],
        )
        self.assertEqual(
            queue_path["delivery_evidence"]["default_message_time_to_live"],
            "P14D",
        )

        subscription_path = paths_by_type[AzureResourceType.SERVICE_BUS_SUBSCRIPTION]
        self.assertEqual(
            subscription_path["target_model_evidence_addresses"],
            [
                "azurerm_servicebus_namespace.orders",
                "azurerm_servicebus_topic.orders",
                "azurerm_servicebus_subscription.orders",
            ],
        )
        self.assertEqual(
            subscription_path["delivery_evidence"]["default_message_time_to_live"],
            "P7D",
        )

    def test_namespace_assignment_with_no_consumable_descendants_emits_no_path(
        self,
    ) -> None:
        facts = _workload_facts(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                _web_app(),
                _receiver_assignment(),
            ]
        )

        self.assertEqual(
            facts.app_service_service_bus_message_removal_paths,
            [],
        )

    def test_direct_queue_and_subscription_scopes_preserve_exact_ancestry(
        self,
    ) -> None:
        cases = (
            (
                "queue",
                [
                    _namespace(),
                    _queue(),
                    _web_app(),
                    _receiver_assignment(scope="azurerm_servicebus_queue.orders.id"),
                ],
                "azurerm_servicebus_queue.orders",
                "queue_message_namespace",
                [
                    "azurerm_servicebus_namespace.orders",
                    "azurerm_servicebus_queue.orders",
                ],
            ),
            (
                "subscription",
                [
                    _namespace(),
                    _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                    _subscription_with_delivery(),
                    _web_app(),
                    _receiver_assignment(scope="azurerm_servicebus_subscription.orders.id"),
                ],
                "azurerm_servicebus_subscription.orders",
                "subscription_message_namespace",
                [
                    "azurerm_servicebus_namespace.orders",
                    "azurerm_servicebus_topic.orders",
                    "azurerm_servicebus_subscription.orders",
                ],
            ),
        )

        for scope_type, resources, target, granularity, ancestry in cases:
            with self.subTest(scope_type=scope_type):
                facts = _workload_facts(resources)
                self.assertEqual(
                    len(facts.app_service_service_bus_message_removal_paths),
                    1,
                )
                path = facts.app_service_service_bus_message_removal_paths[0]
                self.assertEqual(path["operation"], _RECEIVE)
                self.assertEqual(
                    path["operation_class"],
                    "destructive_message_receive",
                )
                self.assertEqual(path["management_effect"], "disruption")
                self.assertEqual(path["scope_type"], scope_type)
                self.assertEqual(path["target_granularity"], granularity)
                self.assertEqual(path["service_bus_resource_address"], target)
                self.assertEqual(
                    path["service_bus_namespace_address"],
                    "azurerm_servicebus_namespace.orders",
                )
                self.assertEqual(
                    path["target_model_evidence_addresses"],
                    ancestry,
                )
                self.assertEqual(path["matched_data_actions"], [_RECEIVE])
                self.assertTrue(path["receive_and_delete_capability"])
                self.assertTrue(path["peek_lock_complete_capability"])
                self.assertEqual(
                    path["runtime_receive_mode_selection"],
                    "not_plan_visible",
                )
                self.assertIsNone(path["complete_lock_token_value"])

    def test_user_assigned_identity_and_custom_role_lineage_are_preserved(
        self,
    ) -> None:
        facts = _workload_facts(
            [
                _namespace(),
                _queue(),
                _user_assigned_identity(),
                _function_app(),
                _custom_role(
                    data_actions=[
                        "Microsoft.ServiceBus/namespaces/messages/send/action",
                        _RECEIVE,
                    ]
                ),
                _role_assignment(
                    principal_id=_USER_PRINCIPAL_ID,
                    scope="azurerm_servicebus_queue.orders.id",
                    role_name=None,
                    role_definition_id=("azurerm_role_definition.service_bus_operator.role_definition_resource_id"),
                ),
            ],
            address="azurerm_linux_function_app.orders_worker",
        )

        path = facts.app_service_service_bus_message_removal_paths[0]
        self.assertEqual(path["identity_kind"], "user_assigned")
        self.assertEqual(
            path["identity_address"],
            "azurerm_user_assigned_identity.orders_runtime",
        )
        self.assertEqual(path["principal_id"], _USER_PRINCIPAL_ID)
        self.assertEqual(path["role_kind"], "custom")
        self.assertEqual(
            path["role_definition_address"],
            "azurerm_role_definition.service_bus_operator",
        )
        self.assertEqual(
            path["authorization_source_addresses"],
            [
                "azurerm_role_assignment.orders_messaging",
                "azurerm_role_definition.service_bus_operator",
            ],
        )
        self.assertEqual(
            path["custom_role_data_actions"],
            [
                "Microsoft.ServiceBus/namespaces/messages/send/action",
                _RECEIVE,
            ],
        )
        self.assertEqual(path["matched_data_actions"], [_RECEIVE])
        self.assertEqual(
            path["custom_role_assignable_scope_compatibility_state"],
            "compatible",
        )

    def test_sender_conditional_and_receive_exclusion_do_not_become_settlement(
        self,
    ) -> None:
        sender = _workload_facts(
            [
                _namespace(),
                _queue(),
                _web_app(),
                _role_assignment(
                    scope="azurerm_servicebus_queue.orders.id",
                    role_name="Azure Service Bus Data Sender",
                    role_definition_id=_SENDER_ROLE_ID,
                ),
            ]
        )
        conditional = _workload_facts(
            [
                _namespace(),
                _queue(),
                _web_app(),
                _receiver_assignment(
                    scope="azurerm_servicebus_queue.orders.id",
                    condition=("@Resource[Microsoft.ServiceBus/namespaces/queues:name] StringEquals 'orders'"),
                ),
            ]
        )
        excluded = _workload_facts(
            [
                _namespace(),
                _queue(),
                _web_app(),
                _custom_role(
                    data_actions=["Microsoft.ServiceBus/*"],
                    not_data_actions=[_RECEIVE],
                ),
                _role_assignment(
                    scope="azurerm_servicebus_queue.orders.id",
                    role_name=None,
                    role_definition_id=_CUSTOM_ROLE_ID,
                ),
            ]
        )

        self.assertEqual(sender.app_service_service_bus_message_removal_paths, [])
        self.assertEqual(excluded.app_service_service_bus_message_removal_paths, [])
        self.assertEqual(
            conditional.app_service_service_bus_message_removal_paths,
            [],
        )
        self.assertTrue(conditional.app_service_service_bus_message_removal_path_uncertainties)

    def test_auto_forwarding_gates_direct_queue_and_subscription_settlement(self) -> None:
        queue_facts = _workload_facts(
            [
                _namespace(),
                _queue(forward_to="azurerm_servicebus_queue.archive.id"),
                _web_app(),
                _receiver_assignment(scope="azurerm_servicebus_queue.orders.id"),
            ]
        )
        self.assertEqual(queue_facts.app_service_service_bus_message_removal_paths, [])
        self.assertFalse(queue_facts.app_service_service_bus_message_removal_path_uncertainties)

        null_forward_queue = _queue()
        null_forward_queue.values["forward_to"] = None
        null_queue_facts = _workload_facts(
            [
                _namespace(),
                null_forward_queue,
                _web_app(),
                _receiver_assignment(scope="azurerm_servicebus_queue.orders.id"),
            ]
        )
        self.assertEqual(len(null_queue_facts.app_service_service_bus_message_removal_paths), 1)
        self.assertEqual(
            null_queue_facts.app_service_service_bus_message_removal_paths[0]["service_bus_auto_forwarding_state"],
            "not_configured",
        )
        self.assertIsNone(null_queue_facts.app_service_service_bus_message_removal_paths[0]["service_bus_forward_to"])

        subscription_facts = _workload_facts(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                _subscription_with_delivery(forward_to="azurerm_servicebus_subscription.archive.id"),
                _web_app(),
                _receiver_assignment(scope="azurerm_servicebus_subscription.orders.id"),
            ]
        )
        self.assertEqual(
            subscription_facts.app_service_service_bus_message_removal_paths,
            [],
        )
        self.assertFalse(
            subscription_facts.app_service_service_bus_message_removal_path_uncertainties,
        )

        unknown_queue = _workload_facts(
            [
                _namespace(),
                _queue(unknown_forward_to=True),
                _web_app(),
                _receiver_assignment(scope="azurerm_servicebus_queue.orders.id"),
            ]
        )
        self.assertEqual(unknown_queue.app_service_service_bus_message_removal_paths, [])
        self.assertTrue(unknown_queue.app_service_service_bus_message_removal_path_uncertainties)

        unknown_subscription = _workload_facts(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                _subscription_with_delivery(unknown_forward_to=True),
                _web_app(),
                _receiver_assignment(scope="azurerm_servicebus_subscription.orders.id"),
            ]
        )
        self.assertEqual(
            unknown_subscription.app_service_service_bus_message_removal_paths,
            [],
        )
        self.assertTrue(
            unknown_subscription.app_service_service_bus_message_removal_path_uncertainties,
        )

    def test_namespace_fanout_excludes_auto_forwarding_children(self) -> None:
        forwarded_queue = _queue(
            forward_to="azurerm_servicebus_queue.orders.id",
        )
        forwarded_queue.address = "azurerm_servicebus_queue.forwarded"
        forwarded_queue.name = "forwarded"
        forwarded_queue.values["id"] = f"{_NAMESPACE_ID}/queues/forwarded"
        forwarded_queue.values["name"] = "forwarded"

        facts = _workload_facts(
            [
                _namespace(),
                _queue(),
                forwarded_queue,
                _web_app(),
                _receiver_assignment(),
            ]
        )

        paths = facts.app_service_service_bus_message_removal_paths
        self.assertEqual(len(paths), 1)
        self.assertEqual(
            paths[0]["service_bus_resource_address"],
            "azurerm_servicebus_queue.orders",
        )
        self.assertEqual(
            paths[0]["service_bus_auto_forwarding_state"],
            "not_configured",
        )
        self.assertIsNone(paths[0]["service_bus_forward_to"])

    def test_entity_status_gates_queue_and_subscription_settlement(self) -> None:
        for status in ("Active", "SendDisabled"):
            with self.subTest(target="queue", status=status):
                facts = _workload_facts(
                    [
                        _namespace(),
                        _queue(status=status),
                        _web_app(),
                        _receiver_assignment(
                            scope="azurerm_servicebus_queue.orders.id",
                        ),
                    ]
                )
                self.assertEqual(len(facts.app_service_service_bus_message_removal_paths), 1)
                self.assertEqual(
                    facts.app_service_service_bus_message_removal_paths[0]["service_bus_entity_status"],
                    status,
                )

        for status in ("ReceiveDisabled", "Disabled"):
            with self.subTest(target="queue", status=status):
                facts = _workload_facts(
                    [
                        _namespace(),
                        _queue(status=status),
                        _web_app(),
                        _receiver_assignment(
                            scope="azurerm_servicebus_queue.orders.id",
                        ),
                    ]
                )
                self.assertEqual(facts.app_service_service_bus_message_removal_paths, [])

        unknown_queue = _workload_facts(
            [
                _namespace(),
                _queue(unknown_status=True),
                _web_app(),
                _receiver_assignment(scope="azurerm_servicebus_queue.orders.id"),
            ]
        )
        self.assertEqual(unknown_queue.app_service_service_bus_message_removal_paths, [])
        self.assertTrue(unknown_queue.app_service_service_bus_message_removal_path_uncertainties)

        for status in ("Active",):
            with self.subTest(target="subscription", status=status):
                facts = _workload_facts(
                    [
                        _namespace(),
                        _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                        _subscription_with_delivery(status=status),
                        _web_app(),
                        _receiver_assignment(
                            scope="azurerm_servicebus_subscription.orders.id",
                        ),
                    ]
                )
                self.assertEqual(len(facts.app_service_service_bus_message_removal_paths), 1)

        for status in ("ReceiveDisabled", "Disabled"):
            with self.subTest(target="subscription", status=status):
                facts = _workload_facts(
                    [
                        _namespace(),
                        _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                        _subscription_with_delivery(status=status),
                        _web_app(),
                        _receiver_assignment(
                            scope="azurerm_servicebus_subscription.orders.id",
                        ),
                    ]
                )
                self.assertEqual(facts.app_service_service_bus_message_removal_paths, [])

        unknown_subscription = _workload_facts(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                _subscription_with_delivery(unknown_status=True),
                _web_app(),
                _receiver_assignment(
                    scope="azurerm_servicebus_subscription.orders.id",
                ),
            ]
        )
        self.assertEqual(
            unknown_subscription.app_service_service_bus_message_removal_paths,
            [],
        )
        self.assertTrue(unknown_subscription.app_service_service_bus_message_removal_path_uncertainties)

    def test_custom_role_assignable_scopes_cover_direct_and_namespace_targets(
        self,
    ) -> None:
        queue_facts = _workload_facts(
            [
                _namespace(),
                _queue(),
                _web_app(),
                _custom_role_with_assignable_scopes(["/subscriptions/sub-0001"]),
                _custom_receiver_assignment(
                    scope="azurerm_servicebus_queue.orders.id",
                ),
            ]
        )
        self.assertEqual(len(queue_facts.app_service_service_bus_message_removal_paths), 1)
        self.assertEqual(
            queue_facts.app_service_service_bus_message_removal_paths[0][
                "custom_role_assignable_scope_compatibility_state"
            ],
            "compatible",
        )

        subscription_facts = _workload_facts(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                _subscription_with_delivery(),
                _web_app(),
                _custom_role_with_assignable_scopes(["/subscriptions/sub-0001"]),
                _custom_receiver_assignment(
                    scope="azurerm_servicebus_subscription.orders.id",
                ),
            ]
        )
        self.assertEqual(
            len(subscription_facts.app_service_service_bus_message_removal_paths),
            1,
        )
        self.assertEqual(
            subscription_facts.app_service_service_bus_message_removal_paths[0][
                "custom_role_assignable_scope_compatibility_state"
            ],
            "compatible",
        )

        namespace_facts = _workload_facts(
            [
                _namespace(),
                _queue(),
                _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                _subscription_with_delivery(),
                _web_app(),
                _custom_role_with_assignable_scopes(["/subscriptions/sub-0001"]),
                _custom_receiver_assignment(
                    scope="azurerm_servicebus_namespace.orders.id",
                ),
            ]
        )
        self.assertEqual(
            len(namespace_facts.app_service_service_bus_message_removal_paths),
            2,
        )
        self.assertEqual(
            {
                path["custom_role_assignable_scope_compatibility_state"]
                for path in namespace_facts.app_service_service_bus_message_removal_paths
            },
            {"compatible"},
        )
        self.assertEqual(
            {path["assignment_scope_kind"] for path in namespace_facts.app_service_service_bus_message_removal_paths},
            {"namespace"},
        )

    def test_custom_role_assignable_scope_rejects_outside_and_unknown_scopes(
        self,
    ) -> None:
        outside = _workload_facts(
            [
                _namespace(),
                _queue(),
                _web_app(),
                _custom_role_with_assignable_scopes(["/subscriptions/other"]),
                _custom_receiver_assignment(
                    scope="azurerm_servicebus_queue.orders.id",
                ),
            ]
        )
        self.assertEqual(outside.app_service_service_bus_message_removal_paths, [])

        unknown = _workload_facts(
            [
                _namespace(),
                _queue(),
                _web_app(),
                _custom_role_with_assignable_scopes(
                    ["/subscriptions/sub-0001"],
                    unknown_assignable_scopes=True,
                ),
                _custom_receiver_assignment(
                    scope="azurerm_servicebus_queue.orders.id",
                ),
            ]
        )
        self.assertEqual(unknown.app_service_service_bus_message_removal_paths, [])
        self.assertTrue(unknown.app_service_service_bus_message_removal_path_uncertainties)

    def test_namespace_fanout_surfaces_unresolved_child_identity_or_ancestry(
        self,
    ) -> None:
        unknown_queue = _workload_facts(
            [
                _namespace(),
                _queue(unknown_entity_id=True),
                _web_app(),
                _receiver_assignment(),
            ]
        )
        self.assertEqual(
            unknown_queue.app_service_service_bus_message_removal_paths,
            [],
        )
        self.assertTrue(
            any(
                "entity identity is unresolved" in uncertainty
                for uncertainty in unknown_queue.app_service_service_bus_message_removal_path_uncertainties
            )
        )

        unknown_topic = _workload_facts(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                _subscription_with_delivery(unknown_topic=True),
                _web_app(),
                _receiver_assignment(),
            ]
        )
        self.assertEqual(
            unknown_topic.app_service_service_bus_message_removal_paths,
            [],
        )
        self.assertTrue(unknown_topic.app_service_service_bus_message_removal_path_uncertainties)

    def test_delivery_posture_is_preserved_without_claiming_recovery(self) -> None:
        facts = _workload_facts(
            [
                _namespace(),
                _queue(),
                _web_app(),
                _receiver_assignment(scope="azurerm_servicebus_queue.orders.id"),
            ]
        )

        delivery = facts.app_service_service_bus_message_removal_paths[0]["delivery_evidence"]
        self.assertEqual(delivery["default_message_time_to_live"], "P14D")
        self.assertEqual(delivery["lock_duration"], "PT2M")
        self.assertEqual(delivery["max_delivery_count"], 8)
        self.assertTrue(delivery["dead_lettering_on_message_expiration"])
        self.assertEqual(
            delivery["removed_message_recovery_state"],
            "not_established_by_modeled_service_bus_delivery_controls",
        )
        self.assertEqual(delivery["uncertainties"], [])

    def test_unknown_delivery_posture_does_not_suppress_settlement_authority(
        self,
    ) -> None:
        facts = _workload_facts(
            [
                _namespace(),
                _queue(unknown_delivery=True),
                _web_app(),
                _receiver_assignment(scope="azurerm_servicebus_queue.orders.id"),
            ]
        )

        self.assertEqual(
            len(facts.app_service_service_bus_message_removal_paths),
            1,
        )
        path = facts.app_service_service_bus_message_removal_paths[0]
        delivery = path["delivery_evidence"]
        self.assertIsNone(delivery["default_message_time_to_live"])
        self.assertIsNone(delivery["lock_duration"])
        self.assertIsNone(delivery["max_delivery_count"])
        self.assertIsNone(delivery["dead_lettering_on_message_expiration"])
        self.assertTrue(delivery["uncertainties"])
        self.assertEqual(path["posture_uncertainties"], delivery["uncertainties"])

    def test_private_workload_retains_settlement_path(self) -> None:
        workload = _web_app()
        workload.values["public_network_access_enabled"] = False
        facts = _workload_facts(
            [
                _namespace(),
                _queue(),
                workload,
                _receiver_assignment(scope="azurerm_servicebus_queue.orders.id"),
            ]
        )

        self.assertEqual(
            len(facts.app_service_service_bus_message_removal_paths),
            1,
        )

    def test_settlement_stage_follows_relationships_identity_and_access_paths(
        self,
    ) -> None:
        names = [stage.name for stage in default_azure_decoration_stages()]
        settlement = names.index("model_app_service_service_bus_message_removal_paths")
        for stage_name in (
            "decorate_service_bus_relationships",
            "decorate_managed_identity_role_assignments",
            "model_app_service_service_bus_access_paths",
        ):
            with self.subTest(stage_name=stage_name):
                self.assertLess(names.index(stage_name), settlement)


if __name__ == "__main__":
    unittest.main()
