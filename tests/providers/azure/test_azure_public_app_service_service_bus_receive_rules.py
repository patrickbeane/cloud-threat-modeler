from __future__ import annotations

import unittest

from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _QUEUE_ID,
    _SYSTEM_PRINCIPAL_ID,
    _TOPIC_ID,
    _USER_PRINCIPAL_ID,
    _custom_role,
    _custom_role_assignment,
    _entity,
    _function_app,
    _namespace,
    _role_assignment,
    _subscription,
    _user_assigned_identity,
    _web_app,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import StrideCategory, TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS

_RULE_ID = "azure-public-app-service-service-bus-receive-access"
_RECEIVER_ROLE_ID = (
    "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0"
)
_OWNER_ROLE_ID = (
    "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/090c5cfd-751d-490a-894a-3ce6f1109419"
)
_RECEIVE_DATA_ACTION = "microsoft.servicebus/namespaces/messages/receive/action"


def _public(resource: TerraformResource) -> TerraformResource:
    resource.values["public_network_access_enabled"] = True
    return resource


def _receiver_assignment(
    *,
    principal_id: object = _SYSTEM_PRINCIPAL_ID,
    scope: object = "azurerm_servicebus_namespace.orders.id",
    condition: object | None = None,
) -> TerraformResource:
    return _role_assignment(
        principal_id=principal_id,
        scope=scope,
        role_name="Azure Service Bus Data Receiver",
        role_definition_id=_RECEIVER_ROLE_ID,
        condition=condition,
    )


def _evaluate(resources: list[TerraformResource]):
    inventory = AzureNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )


def _evidence(finding):
    return {item.key: item.values for item in finding.evidence}


class AzurePublicAppServiceServiceBusReceiveRuleTests(unittest.TestCase):
    def test_rule_is_registered(self) -> None:
        registered = {rule_id for group in AZURE_RULE_GROUP_IDS for rule_id in group}

        self.assertIn(_RULE_ID, registered)

    def test_public_system_assigned_app_with_namespace_receiver_is_detected(self) -> None:
        findings = _evaluate(
            [
                _namespace(),
                _public(_web_app()),
                _receiver_assignment(),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.category, StrideCategory.INFORMATION_DISCLOSURE)
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [
                "azurerm_linux_web_app.orders",
                "azurerm_servicebus_namespace.orders",
                "azurerm_role_assignment.orders_messaging",
            ],
        )
        self.assertIn("unconditional modeled RBAC allow assignment", finding.rationale)
        self.assertIn("could attempt message-receive operations", finding.rationale)
        self.assertIn("not guaranteed effective message retrieval", finding.rationale)
        self.assertIn("Azure deny assignments and Service Bus network controls", finding.rationale)
        self.assertIn("Service Bus target itself is not public", finding.rationale)

        evidence = _evidence(finding)
        self.assertIn("public_network_access_enabled=true", evidence["public_endpoint"])
        self.assertTrue(
            any(
                f"principal_id={_SYSTEM_PRINCIPAL_ID}" in value and "role_kind=service_bus_data_receiver" in value
                for value in evidence["runtime_identity"]
            )
        )
        receive_path = evidence["service_bus_receive_paths"][0]
        self.assertIn(
            "service_bus_resource_address=azurerm_servicebus_namespace.orders",
            receive_path,
        )
        self.assertIn(f"receive_permission={_RECEIVE_DATA_ACTION}", receive_path)
        self.assertIn("matched_data_actions=built-in-role", receive_path)
        self.assertIn("resource_scope=exact_service_bus_namespace", receive_path)
        self.assertIn(
            "receive_evaluation=unconditional_modeled_rbac_allow_assignment",
            receive_path,
        )
        self.assertEqual(
            evidence["assessment_scope"],
            [
                ("establishes=unconditional modeled RBAC allow assignment with Azure Service Bus receive permission"),
                ("does_not_establish=effective access after Azure deny assignment or Service Bus network evaluation"),
            ],
        )

    def test_namespace_scope_has_broader_blast_radius_than_exact_entity_scope(self) -> None:
        namespace_findings = _evaluate(
            [
                _namespace(),
                _public(_web_app()),
                _receiver_assignment(),
            ]
        )
        queue_findings = _evaluate(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                _public(_web_app()),
                _receiver_assignment(
                    scope="azurerm_servicebus_queue.orders.id",
                ),
            ]
        )

        namespace_reasoning = namespace_findings[0].severity_reasoning
        queue_reasoning = queue_findings[0].severity_reasoning
        assert namespace_reasoning is not None
        assert queue_reasoning is not None
        self.assertEqual(namespace_reasoning.blast_radius, 2)
        self.assertEqual(queue_reasoning.blast_radius, 1)
        self.assertGreater(namespace_reasoning.final_score, queue_reasoning.final_score)

    def test_public_function_user_identity_with_queue_owner_is_detected(self) -> None:
        findings = _evaluate(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                _user_assigned_identity(),
                _public(_function_app()),
                _role_assignment(
                    principal_id=_USER_PRINCIPAL_ID,
                    scope="azurerm_servicebus_queue.orders.id",
                    role_name="Azure Service Bus Data Owner",
                    role_definition_id=_OWNER_ROLE_ID,
                ),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(
            finding.affected_resources,
            [
                "azurerm_linux_function_app.orders_worker",
                "azurerm_user_assigned_identity.orders_runtime",
                "azurerm_servicebus_namespace.orders",
                "azurerm_servicebus_queue.orders",
                "azurerm_role_assignment.orders_messaging",
            ],
        )
        evidence = _evidence(finding)
        self.assertTrue(
            any(
                "identity_kind=user_assigned" in value and f"principal_id={_USER_PRINCIPAL_ID}" in value
                for value in evidence["runtime_identity"]
            )
        )
        receive_path = evidence["service_bus_receive_paths"][0]
        self.assertIn("queue_address=azurerm_servicebus_queue.orders", receive_path)
        self.assertIn("role_kind=service_bus_data_owner", receive_path)
        self.assertIn("access_classes=send,receive", receive_path)
        self.assertIn("resource_scope=exact_service_bus_queue", receive_path)

    def test_public_app_with_exact_subscription_receiver_is_detected(self) -> None:
        findings = _evaluate(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                _subscription(),
                _public(_web_app()),
                _receiver_assignment(
                    scope="azurerm_servicebus_subscription.orders.id",
                ),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(
            finding.affected_resources,
            [
                "azurerm_linux_web_app.orders",
                "azurerm_servicebus_namespace.orders",
                "azurerm_servicebus_topic.orders",
                "azurerm_servicebus_subscription.orders",
                "azurerm_role_assignment.orders_messaging",
            ],
        )
        receive_path = _evidence(finding)["service_bus_receive_paths"][0]
        self.assertIn("topic_address=azurerm_servicebus_topic.orders", receive_path)
        self.assertIn(
            "subscription_address=azurerm_servicebus_subscription.orders",
            receive_path,
        )
        self.assertIn("resource_scope=exact_service_bus_subscription", receive_path)

    def test_public_app_with_custom_exact_receive_data_action_is_detected(self) -> None:
        findings = _evaluate(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                _public(_web_app()),
                _custom_role(
                    data_actions=["Microsoft.ServiceBus/*/receive/action"],
                ),
                _custom_role_assignment(
                    scope="azurerm_servicebus_queue.orders.id",
                ),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = _evidence(findings[0])
        receive_path = evidence["service_bus_receive_paths"][0]
        self.assertIn("role_kind=custom", receive_path)
        self.assertIn(f"matched_data_actions={_RECEIVE_DATA_ACTION}", receive_path)
        self.assertTrue(
            any(
                "role_definition_address=azurerm_role_definition.service_bus_operator" in value
                and f"matched_data_actions={_RECEIVE_DATA_ACTION}" in value
                for value in evidence["custom_role_permissions"]
            )
        )

    def test_topic_scoped_receiver_and_owner_remain_quiet(self) -> None:
        cases = {
            "topic receiver": [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                _public(_web_app()),
                _receiver_assignment(
                    scope="azurerm_servicebus_topic.orders.id",
                ),
            ],
            "topic owner": [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                _public(_web_app()),
                _role_assignment(
                    scope="azurerm_servicebus_topic.orders.id",
                    role_name="Azure Service Bus Data Owner",
                    role_definition_id=_OWNER_ROLE_ID,
                ),
            ],
        }

        for case, resources in cases.items():
            with self.subTest(case=case):
                self.assertEqual(_evaluate(resources), [])

    def test_non_receiving_and_uncertain_paths_remain_quiet(self) -> None:
        unknown_app = _web_app()
        unknown_app.values["public_network_access_enabled"] = None
        unknown_app.unknown_values["public_network_access_enabled"] = True
        condition = "@Resource[Microsoft.ServiceBus/namespaces:name] StringEquals 'orders-events'"

        cases = {
            "private app": [
                _namespace(),
                _web_app(),
                _receiver_assignment(),
            ],
            "unknown public exposure": [
                _namespace(),
                unknown_app,
                _receiver_assignment(),
            ],
            "sender only": [
                _namespace(),
                _public(_web_app()),
                _role_assignment(),
            ],
            "conditional receiver": [
                _namespace(),
                _public(_web_app()),
                _receiver_assignment(condition=condition),
            ],
            "custom receive excluded": [
                _namespace(),
                _public(_web_app()),
                _custom_role(
                    data_actions=["Microsoft.ServiceBus/*"],
                    not_data_actions=["Microsoft.ServiceBus/*/receive/action"],
                ),
                _custom_role_assignment(
                    scope="azurerm_servicebus_namespace.orders.id",
                ),
            ],
            "unresolved custom permissions": [
                _namespace(),
                _public(_web_app()),
                _custom_role(
                    data_actions=[],
                    unknown_values={"permissions": [{"data_actions": True}]},
                ),
                _custom_role_assignment(
                    scope="azurerm_servicebus_namespace.orders.id",
                ),
            ],
            "external scope": [
                _namespace(),
                _public(_web_app()),
                _receiver_assignment(
                    scope=(
                        "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.ServiceBus/namespaces/external"
                    ),
                ),
            ],
        }

        for case, resources in cases.items():
            with self.subTest(case=case):
                self.assertEqual(_evaluate(resources), [])


if __name__ == "__main__":
    unittest.main()
