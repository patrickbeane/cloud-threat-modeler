from __future__ import annotations

import unittest

from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _QUEUE_ID,
    _TOPIC_ID,
    _custom_role,
    _custom_role_assignment,
    _entity,
    _namespace,
    _role_assignment,
    _subscription,
    _web_app,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import StrideCategory, TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS

_RULE_ID = "azure-public-app-service-service-bus-message-disruption"
_RECEIVE_RULE_ID = "azure-public-app-service-service-bus-receive-access"
_MUTATION_RULE_ID = "azure-public-app-service-service-bus-mutation-access"
_RECEIVE_ROLE_ID = (
    "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0"
)


def _public(resource: TerraformResource) -> TerraformResource:
    resource.values["public_network_access_enabled"] = True
    return resource


def _receiver_assignment(*, scope: object = "azurerm_servicebus_namespace.orders.id") -> TerraformResource:
    return _role_assignment(
        scope=scope,
        role_name="Azure Service Bus Data Receiver",
        role_definition_id=_RECEIVE_ROLE_ID,
    )


def _evaluate(
    resources: list[TerraformResource],
    rule_ids: frozenset[str] = frozenset({_RULE_ID}),
):
    inventory = AzureNormalizer().normalize(resources)
    findings = StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=rule_ids),
    )
    return inventory, findings


def _evidence(finding):
    return {item.key: item.values for item in finding.evidence}


class AzurePublicAppServiceServiceBusMessageDisruptionRuleTests(unittest.TestCase):
    def test_rule_is_registered_as_denial_of_service(self) -> None:
        registered = {rule_id for group in AZURE_RULE_GROUP_IDS for rule_id in group}
        self.assertIn(_RULE_ID, registered)

        _inventory, findings = _evaluate(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                _public(_web_app()),
                _receiver_assignment(scope="azurerm_servicebus_queue.orders.id"),
            ],
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, StrideCategory.DENIAL_OF_SERVICE)

    def test_receiver_authority_emits_disruption_without_mutation_leakage(self) -> None:
        _inventory, findings = _evaluate(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                _public(_web_app()),
                _receiver_assignment(scope="azurerm_servicebus_queue.orders.id"),
            ],
            frozenset({_MUTATION_RULE_ID, _RECEIVE_RULE_ID, _RULE_ID}),
        )

        self.assertEqual(
            {finding.rule_id for finding in findings},
            {_RECEIVE_RULE_ID, _RULE_ID},
        )
        disruption = next(finding for finding in findings if finding.rule_id == _RULE_ID)
        self.assertEqual(disruption.category, StrideCategory.DENIAL_OF_SERVICE)
        self.assertEqual(
            disruption.affected_resources,
            [
                "azurerm_linux_web_app.orders",
                "azurerm_servicebus_namespace.orders",
                "azurerm_servicebus_queue.orders",
                "azurerm_role_assignment.orders_messaging",
            ],
        )
        self.assertIn("receive-and-settle authority", disruption.rationale)
        self.assertNotIn("successful removal", disruption.rationale.split("Delivery evidence")[0])
        evidence = _evidence(disruption)
        self.assertTrue(
            any(
                "service_bus_resource_address=azurerm_servicebus_queue.orders" in value
                and "target_granularity=queue_message_namespace" in value
                and "receive_and_delete_capability=true" in value
                and "peek_lock_complete_capability=true" in value
                for value in evidence["service_bus_message_removal_paths"]
            )
        )
        self.assertTrue(
            any(
                "removed_message_recovery_state=not_established_by_modeled_service_bus_delivery_controls" in value
                for value in evidence["delivery_and_recovery_evidence"]
            )
        )
        self.assertNotIn("service_bus_message_removal_path_uncertainties", evidence)

    def test_namespace_authority_fans_out_to_exact_queue_and_subscription_targets(self) -> None:
        _inventory, findings = _evaluate(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                _subscription(),
                _public(_web_app()),
                _receiver_assignment(),
            ]
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.severity_reasoning.blast_radius, 2)
        paths = _evidence(finding)["service_bus_message_removal_paths"]
        self.assertEqual(len(paths), 2)
        self.assertTrue(all("service_bus_resource_type=azurerm_servicebus_namespace" not in value for value in paths))
        self.assertTrue(any("target_granularity=queue_message_namespace" in value for value in paths))
        self.assertTrue(any("target_granularity=subscription_message_namespace" in value for value in paths))
        self.assertIn("azurerm_servicebus_queue.orders", finding.affected_resources)
        self.assertIn("azurerm_servicebus_subscription.orders", finding.affected_resources)
        self.assertIn("azurerm_servicebus_topic.orders", finding.affected_resources)

    def test_private_app_keeps_settlement_paths_but_emits_no_finding(self) -> None:
        inventory, findings = _evaluate(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                _web_app(),
                _receiver_assignment(scope="azurerm_servicebus_queue.orders.id"),
            ]
        )

        app = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert app is not None
        self.assertEqual(len(azure_facts(app).app_service_service_bus_message_removal_paths), 1)
        self.assertEqual(findings, [])

    def test_current_target_status_rejects_stale_settlement_path(self) -> None:
        inventory, _findings = _evaluate(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                _public(_web_app()),
                _receiver_assignment(scope="azurerm_servicebus_queue.orders.id"),
            ]
        )
        app = inventory.get_by_address("azurerm_linux_web_app.orders")
        queue = inventory.get_by_address("azurerm_servicebus_queue.orders")
        assert app is not None
        assert queue is not None
        paths = [dict(path) for path in azure_facts(app).app_service_service_bus_message_removal_paths]
        paths[0]["service_bus_entity_status"] = "Disabled"
        azure_facts(app).set_app_service_service_bus_message_removal_paths(paths)

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
        )
        self.assertEqual(findings, [])

    def test_current_access_evidence_rejects_stale_settlement_path(self) -> None:
        inventory, _findings = _evaluate(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                _public(_web_app()),
                _receiver_assignment(scope="azurerm_servicebus_queue.orders.id"),
            ]
        )
        app = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert app is not None
        azure_facts(app).set_app_service_service_bus_access_paths([])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
        )
        self.assertEqual(findings, [])

    def test_current_unknown_assignment_condition_rejects_cached_settlement_path(self) -> None:
        for uncertainty in (
            "condition is unknown after planning",
            "condition_version is unknown after planning",
        ):
            with self.subTest(uncertainty=uncertainty):
                inventory, _findings = _evaluate(
                    [
                        _namespace(),
                        _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                        _public(_web_app()),
                        _receiver_assignment(scope="azurerm_servicebus_queue.orders.id"),
                    ]
                )
                assignment = inventory.get_by_address("azurerm_role_assignment.orders_messaging")
                assert assignment is not None
                azure_facts(assignment).extend_key_vault_authorization_uncertainties([uncertainty])

                findings = StrideRuleEngine().evaluate(
                    inventory,
                    [],
                    rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
                )
                self.assertEqual(findings, [])

    def test_custom_role_settlement_path_is_revalidated_and_emits(self) -> None:
        _inventory, findings = _evaluate(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                _public(_web_app()),
                _custom_role(data_actions=["Microsoft.ServiceBus/*/receive/action"]),
                _custom_role_assignment(scope="azurerm_servicebus_queue.orders.id"),
            ]
        )

        self.assertEqual(len(findings), 1)
        evidence = _evidence(findings[0])
        self.assertTrue(any("role_kind=custom" in value for value in evidence["service_bus_message_removal_paths"]))
        self.assertTrue(
            any(
                "role_definition_address=azurerm_role_definition.service_bus_operator" in value
                for value in evidence["custom_role_permissions"]
            )
        )


if __name__ == "__main__":
    unittest.main()
