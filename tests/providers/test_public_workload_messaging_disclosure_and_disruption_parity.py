from __future__ import annotations

import json
import unittest
from collections.abc import Mapping, Sequence
from typing import Any, cast

from tests.providers.azure.test_azure_app_service_service_bus_message_removal_paths import (
    _queue as azure_delivery_queue,
)
from tests.providers.azure.test_azure_app_service_service_bus_message_removal_paths import (
    _receiver_assignment as azure_receiver_assignment,
)
from tests.providers.azure.test_azure_app_service_service_bus_message_removal_paths import (
    _subscription_with_delivery as azure_delivery_subscription,
)
from tests.providers.gcp.test_gcp_cloud_run_pubsub_message_removal_paths import (
    _project_iam_member as gcp_project_iam_member,
)
from tests.providers.gcp.test_gcp_cloud_run_pubsub_message_removal_paths import (
    _subscription_iam_binding as gcp_subscription_iam_binding,
)
from tests.providers.test_public_workload_message_removal_boundaries import (
    _AWS_DELETE,
    _AWS_PURGE,
    _AWS_RECEIVE,
    _AZURE_OWNER_ROLE_ID,
    _AZURE_SENDER_ROLE_ID,
    AZURE_QUEUE_ID,
    AZURE_TOPIC_ID,
    _aws_queue_with_delivery_posture,
    _aws_resources,
    _azure_queue_resources,
    _gcp_subscription_resources,
    _gcp_subscription_with_delivery_posture,
    _gcp_workload,
    _public_azure_app,
    aws_queue,
    azure_custom_role,
    azure_custom_role_assignment,
    azure_entity,
    azure_namespace,
    gcp_custom_role,
    gcp_public_invoker,
    gcp_subscription,
    gcp_subscription_iam_member,
    gcp_topic,
    gcp_topic_iam_member,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import Finding, ResourceInventory, StrideCategory, TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

AWS_TAMPERING_RULE = "aws-public-ecs-messaging-mutation-access"
AWS_DISCLOSURE_RULE = "aws-public-ecs-sqs-receive-access"
AWS_DISRUPTION_RULE = "aws-public-ecs-sqs-message-disruption"
GCP_TAMPERING_RULE = "gcp-public-cloud-run-pubsub-mutation-access"
GCP_DISCLOSURE_RULE = "gcp-public-cloud-run-pubsub-consume-access"
GCP_DISRUPTION_RULE = "gcp-public-cloud-run-pubsub-message-disruption"
AZURE_TAMPERING_RULE = "azure-public-app-service-service-bus-mutation-access"
AZURE_DISCLOSURE_RULE = "azure-public-app-service-service-bus-receive-access"
AZURE_DISRUPTION_RULE = "azure-public-app-service-service-bus-message-disruption"

_RULE_IDS = frozenset(
    {
        AWS_TAMPERING_RULE,
        AWS_DISCLOSURE_RULE,
        AWS_DISRUPTION_RULE,
        GCP_TAMPERING_RULE,
        GCP_DISCLOSURE_RULE,
        GCP_DISRUPTION_RULE,
        AZURE_TAMPERING_RULE,
        AZURE_DISCLOSURE_RULE,
        AZURE_DISRUPTION_RULE,
    }
)

_AWS_WORKLOAD_ADDRESS = "aws_ecs_service.orders"
_GCP_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.orders"
_AZURE_WORKLOAD_ADDRESS = "azurerm_linux_web_app.orders"
_GCP_ACKNOWLEDGE = "pubsub.subscriptions.consume"
_AZURE_RECEIVE = "microsoft.servicebus/namespaces/messages/receive/action"


def _flatten(groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for group in groups for rule_id in group)


def _analyze(
    normalizer: ProviderNormalizer,
    resources: list[Any],
    *,
    engine: StrideRuleEngine | None = None,
) -> tuple[ResourceInventory, list[Finding]]:
    inventory = normalizer.normalize(resources)
    findings = (engine or StrideRuleEngine()).evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=_RULE_IDS),
    )
    return inventory, findings


def _evidence(finding: Finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


def _finding_by_rule(findings: Sequence[Finding], rule_id: str) -> Finding:
    matches = [finding for finding in findings if finding.rule_id == rule_id]
    assert len(matches) == 1
    return matches[0]


def _path_state(
    provider: str,
    inventory: ResourceInventory,
) -> tuple[list[Mapping[str, object]], list[Mapping[str, object]], list[str]]:
    if provider == "aws":
        workload = inventory.get_by_address(_AWS_WORKLOAD_ADDRESS)
        assert workload is not None
        facts = aws_facts(workload)
        return (
            [cast(Mapping[str, object], path) for path in facts.ecs_messaging_access_paths],
            [cast(Mapping[str, object], path) for path in facts.ecs_sqs_message_removal_paths],
            list(facts.ecs_sqs_message_removal_path_uncertainties),
        )
    if provider == "gcp":
        workload = inventory.get_by_address(_GCP_WORKLOAD_ADDRESS)
        assert workload is not None
        facts = gcp_facts(workload)
        return (
            [cast(Mapping[str, object], path) for path in facts.cloud_run_pubsub_access_paths],
            [cast(Mapping[str, object], path) for path in facts.cloud_run_pubsub_message_removal_paths],
            list(facts.cloud_run_pubsub_message_removal_path_uncertainties),
        )
    workload = inventory.get_by_address(_AZURE_WORKLOAD_ADDRESS)
    assert workload is not None
    facts = azure_facts(workload)
    return (
        [cast(Mapping[str, object], path) for path in facts.app_service_service_bus_access_paths],
        [cast(Mapping[str, object], path) for path in facts.app_service_service_bus_message_removal_paths],
        list(facts.app_service_service_bus_message_removal_path_uncertainties),
    )


def _path_fingerprint(
    provider: str,
    path: Mapping[str, object],
) -> tuple[object, ...]:
    if provider == "aws":
        target = path.get("queue_address")
        identity = path.get("role_arn")
        sources = path.get("authorization_source_addresses")
    elif provider == "gcp":
        target = path.get("subscription_address")
        identity = path.get("service_account_email")
        sources = path.get("iam_source_addresses")
    else:
        target = path.get("service_bus_resource_address")
        identity = path.get("principal_id")
        sources = path.get("authorization_source_addresses")
    source_tuple = tuple(value for value in sources if isinstance(value, str)) if isinstance(sources, list) else ()
    return (
        provider,
        path.get("operation"),
        path.get("target_scope"),
        target,
        identity,
        source_tuple,
    )


def _finding_payload(findings: Sequence[Finding]) -> list[dict[str, object]]:
    return [
        {
            "rule_id": finding.rule_id,
            "category": finding.category.value,
            "affected_resources": finding.affected_resources,
            "rationale": finding.rationale,
            "evidence": _evidence(finding),
        }
        for finding in findings
    ]


class PublicWorkloadMessagingDisclosureAndDisruptionParityTests(unittest.TestCase):
    """Pin shared outcomes while retaining provider-native removal semantics."""

    def test_provider_local_rule_families_are_registered(self) -> None:
        self.assertTrue({AWS_TAMPERING_RULE, AWS_DISCLOSURE_RULE, AWS_DISRUPTION_RULE} <= _flatten(AWS_RULE_GROUP_IDS))
        self.assertTrue({GCP_TAMPERING_RULE, GCP_DISCLOSURE_RULE, GCP_DISRUPTION_RULE} <= _flatten(GCP_RULE_GROUP_IDS))
        self.assertTrue(
            {AZURE_TAMPERING_RULE, AZURE_DISCLOSURE_RULE, AZURE_DISRUPTION_RULE} <= _flatten(AZURE_RULE_GROUP_IDS)
        )

    def test_send_or_publish_only_emits_tampering(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources("sqs:SendMessage"),
                AWS_TAMPERING_RULE,
            ),
            (
                "gcp",
                GcpNormalizer(),
                [
                    _gcp_workload(),
                    gcp_public_invoker(),
                    gcp_topic(),
                    gcp_topic_iam_member(),
                ],
                GCP_TAMPERING_RULE,
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_queue_resources(
                    role_name="Azure Service Bus Data Sender",
                    role_definition_id=_AZURE_SENDER_ROLE_ID,
                ),
                AZURE_TAMPERING_RULE,
            ),
        )

        for provider, normalizer, resources, expected_rule in cases:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                _access_paths, removal_paths, _uncertainties = _path_state(
                    provider,
                    inventory,
                )

                self.assertEqual(removal_paths, [])
                self.assertEqual(
                    [finding.rule_id for finding in findings],
                    [expected_rule],
                )
                self.assertEqual(findings[0].category, StrideCategory.TAMPERING)

    def test_receive_and_removal_capability_preserves_native_category_coupling(
        self,
    ) -> None:
        cases = (
            (
                "aws-receive-only",
                "aws",
                AwsNormalizer(),
                _aws_resources(_AWS_RECEIVE),
                {AWS_DISCLOSURE_RULE},
                0,
            ),
            (
                "aws-delete-without-receive",
                "aws",
                AwsNormalizer(),
                _aws_resources(_AWS_DELETE),
                set(),
                0,
            ),
            (
                "aws-receive-delete",
                "aws",
                AwsNormalizer(),
                _aws_resources([_AWS_RECEIVE, _AWS_DELETE]),
                {AWS_DISCLOSURE_RULE, AWS_DISRUPTION_RULE},
                1,
            ),
            (
                "aws-purge-only",
                "aws",
                AwsNormalizer(),
                _aws_resources(_AWS_PURGE),
                {AWS_DISRUPTION_RULE},
                1,
            ),
            (
                "gcp-consume",
                "gcp",
                GcpNormalizer(),
                _gcp_subscription_resources(),
                {GCP_DISCLOSURE_RULE, GCP_DISRUPTION_RULE},
                1,
            ),
            (
                "azure-receive",
                "azure",
                AzureNormalizer(),
                _azure_queue_resources(),
                {AZURE_DISCLOSURE_RULE, AZURE_DISRUPTION_RULE},
                1,
            ),
        )

        for (
            label,
            provider,
            normalizer,
            resources,
            expected_rules,
            expected_removal_count,
        ) in cases:
            with self.subTest(case=label):
                inventory, findings = _analyze(normalizer, resources)
                access_paths, removal_paths, _uncertainties = _path_state(
                    provider,
                    inventory,
                )

                self.assertTrue(access_paths)
                self.assertEqual(len(removal_paths), expected_removal_count)
                self.assertEqual(
                    {finding.rule_id for finding in findings},
                    expected_rules,
                )
                self.assertNotIn(
                    StrideCategory.TAMPERING,
                    {finding.category for finding in findings},
                )

    def test_mixed_send_receive_and_removal_emit_each_effect_without_operation_leakage(
        self,
    ) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(["sqs:SendMessage", _AWS_RECEIVE, _AWS_DELETE]),
                AWS_TAMPERING_RULE,
                AWS_DISCLOSURE_RULE,
                AWS_DISRUPTION_RULE,
                "messaging_mutation_paths",
                "actions=sqs:SendMessage",
                "sqs_message_removal_paths",
                f"operation={_AWS_DELETE}",
            ),
            (
                "gcp",
                GcpNormalizer(),
                [*_gcp_subscription_resources(), gcp_topic_iam_member()],
                GCP_TAMPERING_RULE,
                GCP_DISCLOSURE_RULE,
                GCP_DISRUPTION_RULE,
                "pubsub_mutation_paths",
                "mutation_classes=publish",
                "pubsub_message_removal_paths",
                f"operation={_GCP_ACKNOWLEDGE}",
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_queue_resources(
                    role_name="Azure Service Bus Data Owner",
                    role_definition_id=_AZURE_OWNER_ROLE_ID,
                ),
                AZURE_TAMPERING_RULE,
                AZURE_DISCLOSURE_RULE,
                AZURE_DISRUPTION_RULE,
                "service_bus_mutation_paths",
                "mutation_classes=send",
                "service_bus_message_removal_paths",
                f"operation={_AZURE_RECEIVE}",
            ),
        )

        for (
            provider,
            normalizer,
            resources,
            tampering_rule,
            disclosure_rule,
            disruption_rule,
            mutation_key,
            mutation_fragment,
            removal_key,
            removal_fragment,
        ) in cases:
            with self.subTest(provider=provider):
                _inventory, findings = _analyze(normalizer, resources)
                by_rule = {finding.rule_id: finding for finding in findings}

                self.assertEqual(
                    set(by_rule),
                    {tampering_rule, disclosure_rule, disruption_rule},
                )
                self.assertEqual(
                    by_rule[tampering_rule].category,
                    StrideCategory.TAMPERING,
                )
                self.assertEqual(
                    by_rule[disclosure_rule].category,
                    StrideCategory.INFORMATION_DISCLOSURE,
                )
                self.assertEqual(
                    by_rule[disruption_rule].category,
                    StrideCategory.DENIAL_OF_SERVICE,
                )
                mutation_records = _evidence(by_rule[tampering_rule])[mutation_key]
                removal_records = _evidence(by_rule[disruption_rule])[removal_key]
                self.assertTrue(any(mutation_fragment in record for record in mutation_records))
                self.assertTrue(any(removal_fragment in record for record in removal_records))
                self.assertNotIn(removal_fragment, json.dumps(mutation_records))

    def test_non_settleable_delivery_modes_preserve_disclosure_without_disruption(
        self,
    ) -> None:
        push_subscription = gcp_subscription()
        assert isinstance(push_subscription, TerraformResource)
        push_subscription.values["push_config"] = [{"push_endpoint": "https://worker.example.test"}]
        cases = (
            (
                "gcp-push",
                "gcp",
                GcpNormalizer(),
                _gcp_subscription_resources(subscription=push_subscription),
                GCP_DISCLOSURE_RULE,
            ),
            (
                "azure-auto-forward",
                "azure",
                AzureNormalizer(),
                [
                    azure_namespace(),
                    azure_delivery_queue(forward_to="azurerm_servicebus_queue.archive.id"),
                    _public_azure_app(),
                    azure_receiver_assignment(scope="azurerm_servicebus_queue.orders.id"),
                ],
                AZURE_DISCLOSURE_RULE,
            ),
        )

        for label, provider, normalizer, resources, disclosure_rule in cases:
            with self.subTest(case=label):
                inventory, findings = _analyze(normalizer, resources)
                access_paths, removal_paths, _uncertainties = _path_state(
                    provider,
                    inventory,
                )

                self.assertTrue(access_paths)
                self.assertEqual(removal_paths, [])
                self.assertEqual(
                    [finding.rule_id for finding in findings],
                    [disclosure_rule],
                )

    def test_private_workloads_keep_access_and_removal_paths_without_public_findings(
        self,
    ) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(
                    [_AWS_RECEIVE, _AWS_DELETE],
                    internal=True,
                ),
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_subscription_resources(public=False),
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_queue_resources(public=False),
            ),
        )

        for provider, normalizer, resources in cases:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                access_paths, removal_paths, _uncertainties = _path_state(
                    provider,
                    inventory,
                )

                self.assertTrue(access_paths)
                self.assertTrue(removal_paths)
                self.assertEqual(findings, [])

    def test_nondeterministic_or_unresolved_removal_authority_is_not_promoted(
        self,
    ) -> None:
        condition = {
            "title": "runtime-window",
            "expression": "request.time < timestamp('2030-01-01T00:00:00Z')",
        }
        cases = (
            (
                "aws-conditional",
                "aws",
                AwsNormalizer(),
                _aws_resources(
                    [_AWS_RECEIVE, _AWS_DELETE],
                    condition={"StringEquals": {"aws:PrincipalTag/environment": "production"}},
                ),
            ),
            (
                "aws-incomplete",
                "aws",
                AwsNormalizer(),
                _aws_resources(
                    [_AWS_RECEIVE, _AWS_DELETE],
                    incomplete=True,
                ),
            ),
            (
                "gcp-conditional",
                "gcp",
                GcpNormalizer(),
                _gcp_subscription_resources(condition=condition),
            ),
            (
                "gcp-unresolved-role",
                "gcp",
                GcpNormalizer(),
                _gcp_subscription_resources(role="projects/tfstride-demo/roles/missingMessagingRole"),
            ),
            (
                "azure-conditional",
                "azure",
                AzureNormalizer(),
                _azure_queue_resources(
                    condition=("@Resource[Microsoft.ServiceBus/namespaces/queues:name] StringEquals 'orders'")
                ),
            ),
        )

        for label, provider, normalizer, resources in cases:
            with self.subTest(case=label):
                inventory, findings = _analyze(normalizer, resources)
                _access_paths, removal_paths, uncertainties = _path_state(
                    provider,
                    inventory,
                )

                self.assertEqual(removal_paths, [])
                self.assertTrue(uncertainties)
                self.assertNotIn(
                    {
                        "aws": AWS_DISRUPTION_RULE,
                        "gcp": GCP_DISRUPTION_RULE,
                        "azure": AZURE_DISRUPTION_RULE,
                    }[provider],
                    {finding.rule_id for finding in findings},
                )

    def test_denied_or_ambiguous_authority_does_not_become_disruption(
        self,
    ) -> None:
        cases = (
            (
                "aws-explicit-deny",
                "aws",
                AwsNormalizer(),
                _aws_resources(
                    [_AWS_RECEIVE, _AWS_DELETE],
                    deny_actions=_AWS_DELETE,
                ),
                {AWS_DISCLOSURE_RULE},
            ),
            (
                "gcp-overlapping-managers",
                "gcp",
                GcpNormalizer(),
                [
                    *_gcp_subscription_resources(),
                    gcp_subscription_iam_binding(),
                ],
                {GCP_DISCLOSURE_RULE},
            ),
            (
                "azure-custom-role-exclusion",
                "azure",
                AzureNormalizer(),
                [
                    azure_namespace(),
                    azure_entity(
                        AzureResourceType.SERVICE_BUS_QUEUE,
                        AZURE_QUEUE_ID,
                    ),
                    _public_azure_app(),
                    azure_custom_role(
                        data_actions=[_AZURE_RECEIVE],
                        not_data_actions=[_AZURE_RECEIVE],
                    ),
                    azure_custom_role_assignment(scope="azurerm_servicebus_queue.orders.id"),
                ],
                set(),
            ),
        )

        for label, provider, normalizer, resources, expected_rules in cases:
            with self.subTest(case=label):
                inventory, findings = _analyze(normalizer, resources)
                _access_paths, removal_paths, _uncertainties = _path_state(
                    provider,
                    inventory,
                )

                self.assertEqual(removal_paths, [])
                self.assertEqual(
                    {finding.rule_id for finding in findings},
                    expected_rules,
                )

    def test_entity_destruction_stays_outside_message_removal_disruption(
        self,
    ) -> None:
        custom_role_name = "projects/tfstride-demo/roles/cloudRunMessaging"
        cases = (
            (
                "aws-delete-queue",
                "aws",
                AwsNormalizer(),
                _aws_resources("sqs:DeleteQueue"),
                AWS_DISRUPTION_RULE,
            ),
            (
                "gcp-delete-subscription",
                "gcp",
                GcpNormalizer(),
                [
                    _gcp_workload(),
                    gcp_public_invoker(),
                    gcp_topic(),
                    gcp_subscription(),
                    gcp_custom_role(permissions=["pubsub.subscriptions.delete"]),
                    gcp_subscription_iam_member(role=custom_role_name),
                ],
                GCP_DISRUPTION_RULE,
            ),
            (
                "azure-delete-queue",
                "azure",
                AzureNormalizer(),
                [
                    azure_namespace(),
                    azure_entity(
                        AzureResourceType.SERVICE_BUS_QUEUE,
                        AZURE_QUEUE_ID,
                    ),
                    _public_azure_app(),
                    azure_custom_role(data_actions=["Microsoft.ServiceBus/namespaces/queues/delete"]),
                    azure_custom_role_assignment(scope="azurerm_servicebus_queue.orders.id"),
                ],
                AZURE_DISRUPTION_RULE,
            ),
        )

        for label, provider, normalizer, resources, disruption_rule in cases:
            with self.subTest(case=label):
                inventory, findings = _analyze(normalizer, resources)
                _access_paths, removal_paths, _uncertainties = _path_state(
                    provider,
                    inventory,
                )

                self.assertEqual(removal_paths, [])
                self.assertNotIn(
                    disruption_rule,
                    {finding.rule_id for finding in findings},
                )

    def test_native_target_and_delivery_semantics_remain_operation_specific(
        self,
    ) -> None:
        aws_inventory, aws_findings = _analyze(
            AwsNormalizer(),
            _aws_resources(
                [_AWS_RECEIVE, _AWS_DELETE, _AWS_PURGE],
                queue=_aws_queue_with_delivery_posture(),
            ),
        )
        _aws_access, aws_paths, _aws_uncertainties = _path_state(
            "aws",
            aws_inventory,
        )
        paths_by_operation = {path["operation"]: path for path in aws_paths}
        delete_path = paths_by_operation[_AWS_DELETE]
        purge_path = paths_by_operation[_AWS_PURGE]
        self.assertEqual(delete_path["prerequisite_operation"], _AWS_RECEIVE)
        self.assertEqual(
            delete_path["receipt_handle_source"],
            "runtime_receive_response",
        )
        self.assertIsNone(delete_path["receipt_handle_value"])
        self.assertEqual(
            delete_path["target_granularity"],
            "queue_received_message_namespace",
        )
        self.assertIsNone(purge_path["prerequisite_operation"])
        self.assertEqual(
            purge_path["target_granularity"],
            "queue_message_namespace",
        )
        aws_finding = _finding_by_rule(aws_findings, AWS_DISRUPTION_RULE)
        aws_fingerprints = [_path_fingerprint("aws", path) for path in aws_paths]
        self.assertEqual(len(aws_fingerprints), len(set(aws_fingerprints)))
        self.assertEqual(aws_finding.severity_reasoning.blast_radius, 1)
        self.assertEqual(
            aws_finding.affected_resources.count("aws_sqs_queue.orders"),
            1,
        )
        aws_delivery = _evidence(aws_finding)["delivery_and_recovery_evidence"]
        self.assertEqual(len(aws_delivery), 2)
        self.assertTrue(
            all(
                "redrive_state=configured" in record
                and "successful_removal_not_established=true" in record
                and "successful_recovery_not_established=true" in record
                for record in aws_delivery
            )
        )

        gcp_inventory, gcp_findings = _analyze(
            GcpNormalizer(),
            _gcp_subscription_resources(
                subscription=_gcp_subscription_with_delivery_posture(),
            ),
        )
        _gcp_access, gcp_paths, _gcp_uncertainties = _path_state(
            "gcp",
            gcp_inventory,
        )
        self.assertEqual(len(gcp_paths), 1)
        gcp_path = gcp_paths[0]
        self.assertEqual(gcp_path["operation"], _GCP_ACKNOWLEDGE)
        self.assertEqual(
            gcp_path["target_granularity"],
            "subscription_message_namespace",
        )
        self.assertEqual(
            gcp_path["acknowledgement_id_source"],
            "runtime_message_delivery",
        )
        self.assertIsNone(gcp_path["acknowledgement_id_value"])
        gcp_delivery = _evidence(_finding_by_rule(gcp_findings, GCP_DISRUPTION_RULE))["delivery_and_recovery_evidence"]
        self.assertTrue(
            any(
                "acknowledged_message_replay_state=retained_by_subscription" in record
                and "dead_letter_policy_state=configured" in record
                and "successful_acknowledgement_not_established=true" in record
                and "successful_recovery_not_established=true" in record
                for record in gcp_delivery
            )
        )

        azure_inventory, azure_findings = _analyze(
            AzureNormalizer(),
            [
                azure_namespace(),
                azure_delivery_queue(),
                _public_azure_app(),
                azure_receiver_assignment(scope="azurerm_servicebus_queue.orders.id"),
            ],
        )
        _azure_access, azure_paths, _azure_uncertainties = _path_state(
            "azure",
            azure_inventory,
        )
        self.assertEqual(len(azure_paths), 1)
        azure_path = azure_paths[0]
        self.assertEqual(azure_path["operation"], _AZURE_RECEIVE)
        self.assertEqual(
            azure_path["target_granularity"],
            "queue_message_namespace",
        )
        self.assertTrue(azure_path["receive_and_delete_capability"])
        self.assertTrue(azure_path["peek_lock_complete_capability"])
        self.assertEqual(
            azure_path["complete_lock_token_source"],
            "runtime_peek_lock_receive",
        )
        self.assertIsNone(azure_path["complete_lock_token_value"])
        azure_delivery = _evidence(_finding_by_rule(azure_findings, AZURE_DISRUPTION_RULE))[
            "delivery_and_recovery_evidence"
        ]
        self.assertTrue(
            any(
                "default_message_time_to_live=P14D" in record
                and "lock_duration=PT2M" in record
                and "removed_message_recovery_state=not_established_by_modeled_service_bus_delivery_controls" in record
                for record in azure_delivery
            )
        )

    def test_unknown_delivery_or_replay_posture_does_not_suppress_authority(
        self,
    ) -> None:
        aws_unknown = aws_queue()
        aws_unknown.unknown_values["redrive_policy"] = True

        gcp_unknown = gcp_subscription()
        assert isinstance(gcp_unknown, TerraformResource)
        gcp_unknown.values["message_retention_duration"] = "86400s"
        gcp_unknown.unknown_values["retain_acked_messages"] = True

        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(
                    [_AWS_RECEIVE, _AWS_DELETE],
                    queue=aws_unknown,
                ),
                AWS_DISRUPTION_RULE,
                "redrive_state=unknown",
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_subscription_resources(subscription=gcp_unknown),
                GCP_DISRUPTION_RULE,
                "acknowledged_message_replay_state=unknown",
            ),
            (
                "azure",
                AzureNormalizer(),
                [
                    azure_namespace(),
                    azure_delivery_queue(unknown_delivery=True),
                    _public_azure_app(),
                    azure_receiver_assignment(scope="azurerm_servicebus_queue.orders.id"),
                ],
                AZURE_DISRUPTION_RULE,
                "default_message_time_to_live=unknown",
            ),
        )

        for provider, normalizer, resources, rule_id, state_fragment in cases:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                _access_paths, removal_paths, _uncertainties = _path_state(
                    provider,
                    inventory,
                )
                finding = _finding_by_rule(findings, rule_id)

                self.assertTrue(removal_paths)
                self.assertTrue(
                    any(
                        state_fragment in record and "uncertainties=none" not in record
                        for record in _evidence(finding)["delivery_and_recovery_evidence"]
                    )
                )

    def test_broad_authorization_fans_out_to_exact_targets_without_duplicate_paths(
        self,
    ) -> None:
        gcp_resources = [
            _gcp_workload(),
            gcp_public_invoker(),
            gcp_topic(),
            gcp_subscription(),
            gcp_subscription(
                "google_pubsub_subscription.archive",
                name="archive",
                reference="projects/tfstride-demo/subscriptions/archive-worker",
            ),
            gcp_project_iam_member(),
        ]
        gcp_inventory, gcp_findings = _analyze(
            GcpNormalizer(),
            gcp_resources,
        )
        _gcp_access, gcp_paths, _gcp_uncertainties = _path_state(
            "gcp",
            gcp_inventory,
        )
        self.assertEqual(len(gcp_paths), 2)
        self.assertEqual(
            {path["subscription_address"] for path in gcp_paths},
            {
                "google_pubsub_subscription.orders",
                "google_pubsub_subscription.archive",
            },
        )
        self.assertEqual(
            {tuple(cast(list[str], path["iam_source_addresses"])) for path in gcp_paths},
            {("google_project_iam_member.project_subscriber",)},
        )
        self.assertEqual(
            _finding_by_rule(
                gcp_findings,
                GCP_DISRUPTION_RULE,
            ).severity_reasoning.blast_radius,
            2,
        )

        azure_inventory, azure_findings = _analyze(
            AzureNormalizer(),
            [
                azure_namespace(),
                azure_delivery_queue(),
                azure_entity(AzureResourceType.SERVICE_BUS_TOPIC, AZURE_TOPIC_ID),
                azure_delivery_subscription(),
                _public_azure_app(),
                azure_receiver_assignment(),
            ],
        )
        _azure_access, azure_paths, _azure_uncertainties = _path_state(
            "azure",
            azure_inventory,
        )
        self.assertEqual(len(azure_paths), 2)
        self.assertEqual(
            {path["service_bus_entity_kind"] for path in azure_paths},
            {"queue", "subscription"},
        )
        self.assertNotIn(
            "azurerm_servicebus_namespace.orders",
            {path["service_bus_resource_address"] for path in azure_paths},
        )
        self.assertEqual(
            _finding_by_rule(
                azure_findings,
                AZURE_DISRUPTION_RULE,
            ).severity_reasoning.blast_radius,
            2,
        )

        for provider, paths in (("gcp", gcp_paths), ("azure", azure_paths)):
            fingerprints = [_path_fingerprint(provider, path) for path in paths]
            self.assertEqual(len(fingerprints), len(set(fingerprints)))

    def test_reused_rule_engine_preserves_provider_isolation_and_excludes_payload_sentinels(
        self,
    ) -> None:
        aws_queue_resource = _aws_queue_with_delivery_posture()
        aws_queue_resource.values["tags"] = {"payload": "aws-message-payload-must-not-leak"}
        gcp_subscription_resource = _gcp_subscription_with_delivery_posture()
        gcp_subscription_resource.values["labels"] = {"payload": "gcp-message-payload-must-not-leak"}
        azure_queue_resource = azure_delivery_queue()
        azure_queue_resource.values["tags"] = {"payload": "azure-message-payload-must-not-leak"}

        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(
                    ["sqs:SendMessage", _AWS_RECEIVE, _AWS_DELETE],
                    queue=aws_queue_resource,
                ),
                {
                    AWS_TAMPERING_RULE,
                    AWS_DISCLOSURE_RULE,
                    AWS_DISRUPTION_RULE,
                },
                ("google_", "azurerm_"),
                "aws-message-payload-must-not-leak",
            ),
            (
                "gcp",
                GcpNormalizer(),
                [
                    *_gcp_subscription_resources(
                        subscription=gcp_subscription_resource,
                    ),
                    gcp_topic_iam_member(),
                ],
                {
                    GCP_TAMPERING_RULE,
                    GCP_DISCLOSURE_RULE,
                    GCP_DISRUPTION_RULE,
                },
                ("aws_", "azurerm_"),
                "gcp-message-payload-must-not-leak",
            ),
            (
                "azure",
                AzureNormalizer(),
                [
                    azure_namespace(),
                    azure_queue_resource,
                    _public_azure_app(),
                    _azure_queue_resources(
                        role_name="Azure Service Bus Data Owner",
                        role_definition_id=_AZURE_OWNER_ROLE_ID,
                    )[-1],
                ],
                {
                    AZURE_TAMPERING_RULE,
                    AZURE_DISCLOSURE_RULE,
                    AZURE_DISRUPTION_RULE,
                },
                ("aws_", "google_"),
                "azure-message-payload-must-not-leak",
            ),
            (
                "aws-second-pass",
                AwsNormalizer(),
                _aws_resources(
                    ["sqs:SendMessage", _AWS_RECEIVE, _AWS_DELETE],
                    queue=aws_queue_resource,
                ),
                {
                    AWS_TAMPERING_RULE,
                    AWS_DISCLOSURE_RULE,
                    AWS_DISRUPTION_RULE,
                },
                ("google_", "azurerm_"),
                "aws-message-payload-must-not-leak",
            ),
        )
        engine = StrideRuleEngine()

        for (
            label,
            normalizer,
            resources,
            expected_rules,
            foreign_prefixes,
            sentinel,
        ) in cases:
            with self.subTest(provider=label):
                provider = label.removesuffix("-second-pass")
                inventory, findings = _analyze(
                    normalizer,
                    resources,
                    engine=engine,
                )
                access_paths, removal_paths, uncertainties = _path_state(
                    provider,
                    inventory,
                )
                payload = json.dumps(
                    {
                        "access_paths": access_paths,
                        "removal_paths": removal_paths,
                        "uncertainties": uncertainties,
                        "findings": _finding_payload(findings),
                    },
                    sort_keys=True,
                )

                self.assertEqual(
                    {finding.rule_id for finding in findings},
                    expected_rules,
                )
                self.assertNotIn(sentinel, payload)
                for prefix in foreign_prefixes:
                    self.assertNotIn(prefix, payload)


if __name__ == "__main__":
    unittest.main()
