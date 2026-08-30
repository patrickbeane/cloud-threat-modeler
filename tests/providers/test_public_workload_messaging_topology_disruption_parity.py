from __future__ import annotations

import json
import unittest
from collections.abc import Mapping, Sequence
from typing import Any, cast

from tests.providers.azure.test_azure_app_service_service_bus_topology_destruction_paths import (
    _management_lock as azure_management_lock,
)
from tests.providers.gcp.test_gcp_cloud_run_pubsub_message_removal_paths import (
    _cross_project_topic_and_subscription,
)
from tests.providers.test_public_workload_messaging_topology_destruction_boundaries import (
    _AWS_DELETE_QUEUE,
    _AWS_DELETE_TOPIC,
    _AZURE_DELETE_NAMESPACE,
    _AZURE_DELETE_QUEUE,
    _AZURE_DELETE_SUBSCRIPTION,
    _AZURE_DELETE_TOPIC,
    _GCP_DELETE_SUBSCRIPTION,
    _GCP_DELETE_TOPIC,
    AWS_QUEUE_ARN,
    AWS_TOPIC_ARN,
    AZURE_NAMESPACE_ID,
    AZURE_QUEUE_ID,
    AZURE_TOPIC_ID,
    GCP_SUBSCRIPTION_ADDRESS,
    GCP_TOPIC_ADDRESS,
    GCP_WORKLOAD_ADDRESS,
    _aws_resources,
    _azure_control_assignment,
    _azure_control_role,
    _azure_workload,
    _gcp_custom_role,
    _gcp_role_name,
    _gcp_workload,
    aws_statement,
    azure_entity,
    azure_namespace,
    azure_subscription,
    gcp_project_iam_member,
    gcp_public_invoker,
    gcp_subscription,
    gcp_subscription_iam_binding,
    gcp_subscription_iam_member,
    gcp_topic,
    gcp_topic_iam_member,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import Finding, ResourceInventory, StrideCategory
from tfstride.providers.aws.metadata import AwsResourceMetadata
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
AWS_MESSAGE_DISRUPTION_RULE = "aws-public-ecs-sqs-message-disruption"
AWS_TOPOLOGY_DISRUPTION_RULE = "aws-public-ecs-messaging-topology-disruption"

GCP_TAMPERING_RULE = "gcp-public-cloud-run-pubsub-mutation-access"
GCP_DISCLOSURE_RULE = "gcp-public-cloud-run-pubsub-consume-access"
GCP_MESSAGE_DISRUPTION_RULE = "gcp-public-cloud-run-pubsub-message-disruption"
GCP_TOPOLOGY_DISRUPTION_RULE = "gcp-public-cloud-run-pubsub-topology-disruption"

AZURE_TAMPERING_RULE = "azure-public-app-service-service-bus-mutation-access"
AZURE_DISCLOSURE_RULE = "azure-public-app-service-service-bus-receive-access"
AZURE_MESSAGE_DISRUPTION_RULE = "azure-public-app-service-service-bus-message-disruption"
AZURE_TOPOLOGY_DISRUPTION_RULE = "azure-public-app-service-service-bus-topology-disruption"

_RULE_IDS = frozenset(
    {
        AWS_TAMPERING_RULE,
        AWS_DISCLOSURE_RULE,
        AWS_MESSAGE_DISRUPTION_RULE,
        AWS_TOPOLOGY_DISRUPTION_RULE,
        GCP_TAMPERING_RULE,
        GCP_DISCLOSURE_RULE,
        GCP_MESSAGE_DISRUPTION_RULE,
        GCP_TOPOLOGY_DISRUPTION_RULE,
        AZURE_TAMPERING_RULE,
        AZURE_DISCLOSURE_RULE,
        AZURE_MESSAGE_DISRUPTION_RULE,
        AZURE_TOPOLOGY_DISRUPTION_RULE,
    }
)

_AWS_WORKLOAD_ADDRESS = "aws_ecs_service.orders"
_AZURE_WORKLOAD_ADDRESS = "azurerm_linux_web_app.orders"
_AWS_SEND = "sqs:SendMessage"
_AWS_RECEIVE = "sqs:ReceiveMessage"
_AWS_DELETE_MESSAGE = "sqs:DeleteMessage"
_GCP_PUBLISH = "pubsub.topics.publish"
_GCP_CONSUME = "pubsub.subscriptions.consume"
_AZURE_SEND = "microsoft.servicebus/namespaces/messages/send/action"
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
    return inventory, _evaluate_inventory(inventory, engine=engine)


def _evaluate_inventory(
    inventory: ResourceInventory,
    *,
    engine: StrideRuleEngine | None = None,
) -> list[Finding]:
    return (engine or StrideRuleEngine()).evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=_RULE_IDS),
    )


def _evidence(finding: Finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


def _finding_by_rule(findings: Sequence[Finding], rule_id: str) -> Finding:
    matches = [finding for finding in findings if finding.rule_id == rule_id]
    assert len(matches) == 1
    return matches[0]


def _topology_state(
    provider: str,
    inventory: ResourceInventory,
) -> tuple[list[Mapping[str, object]], list[str]]:
    if provider == "aws":
        workload = inventory.get_by_address(_AWS_WORKLOAD_ADDRESS)
        assert workload is not None
        facts = aws_facts(workload)
        return (
            [cast(Mapping[str, object], path) for path in facts.ecs_messaging_topology_destruction_paths],
            list(facts.ecs_messaging_topology_destruction_path_uncertainties),
        )
    if provider == "gcp":
        workload = inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert workload is not None
        facts = gcp_facts(workload)
        return (
            [cast(Mapping[str, object], path) for path in facts.cloud_run_pubsub_topology_destruction_paths],
            list(facts.cloud_run_pubsub_topology_destruction_path_uncertainties),
        )

    workload = inventory.get_by_address(_AZURE_WORKLOAD_ADDRESS)
    assert workload is not None
    facts = azure_facts(workload)
    return (
        [cast(Mapping[str, object], path) for path in facts.app_service_service_bus_topology_destruction_paths],
        list(facts.app_service_service_bus_topology_destruction_path_uncertainties),
    )


def _replace_topology_paths(
    provider: str,
    inventory: ResourceInventory,
    paths: Sequence[Mapping[str, object]],
) -> None:
    records = [dict(path) for path in paths]
    if provider == "aws":
        workload = inventory.get_by_address(_AWS_WORKLOAD_ADDRESS)
        assert workload is not None
        aws_facts(workload).set(
            AwsResourceMetadata.ECS_MESSAGING_TOPOLOGY_DESTRUCTION_PATHS,
            records,
        )
        return
    if provider == "gcp":
        workload = inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert workload is not None
        gcp_facts(workload).set_cloud_run_pubsub_topology_destruction_paths(cast(Any, records))
        return

    workload = inventory.get_by_address(_AZURE_WORKLOAD_ADDRESS)
    assert workload is not None
    azure_facts(workload).set_app_service_service_bus_topology_destruction_paths(cast(Any, records))


def _topology_fingerprint(
    provider: str,
    path: Mapping[str, object],
) -> tuple[object, ...]:
    if provider == "aws":
        identity = path.get("role_arn")
        sources = path.get("authorization_source_addresses")
    elif provider == "gcp":
        identity = path.get("service_account_email")
        sources = path.get("iam_source_addresses")
    else:
        identity = path.get("principal_id")
        sources = path.get("authorization_source_addresses")
    source_values = tuple(value for value in sources if isinstance(value, str)) if isinstance(sources, list) else ()
    return (
        provider,
        path.get("operation"),
        path.get("target_scope"),
        path.get("messaging_resource_address") or path.get("service_bus_resource_address"),
        identity,
        source_values,
    )


def _aws_topology_resources(
    *,
    public: bool = True,
    include_queue: bool = True,
    include_topic: bool = True,
) -> list[Any]:
    statements: list[dict[str, Any]] = []
    if include_queue:
        statements.append(
            aws_statement("Allow", _AWS_DELETE_QUEUE, AWS_QUEUE_ARN),
        )
    if include_topic:
        statements.append(
            aws_statement("Allow", _AWS_DELETE_TOPIC, AWS_TOPIC_ARN),
        )
    return _aws_resources(statements, internal=not public)


def _gcp_topology_resources(
    *,
    public: bool = True,
    include_topic: bool = True,
    include_subscription: bool = True,
) -> list[Any]:
    permissions: list[str] = []
    if include_topic:
        permissions.append(_GCP_DELETE_TOPIC)
    if include_subscription:
        permissions.append(_GCP_DELETE_SUBSCRIPTION)
    resources: list[Any] = [
        _gcp_workload(public=public),
        gcp_public_invoker(),
        gcp_topic(),
    ]
    if include_subscription:
        resources.append(gcp_subscription())
    resources.append(_gcp_custom_role(permissions))
    if include_topic:
        resources.append(gcp_topic_iam_member(role=_gcp_role_name()))
    if include_subscription:
        resources.append(
            gcp_subscription_iam_member(role=_gcp_role_name()),
        )
    return resources


def _azure_topology_resources(
    *,
    public: bool = True,
    operations: Sequence[str] = (
        _AZURE_DELETE_NAMESPACE,
        _AZURE_DELETE_QUEUE,
        _AZURE_DELETE_TOPIC,
        _AZURE_DELETE_SUBSCRIPTION,
    ),
) -> list[Any]:
    resources: list[Any] = [
        azure_namespace(),
        azure_entity(AzureResourceType.SERVICE_BUS_QUEUE, AZURE_QUEUE_ID),
        azure_entity(AzureResourceType.SERVICE_BUS_TOPIC, AZURE_TOPIC_ID),
        azure_subscription(),
        _azure_workload(public=public),
        _azure_control_role(actions=list(operations)),
        _azure_control_assignment(),
    ]
    return resources


def _non_topology_resources() -> tuple[
    tuple[str, ProviderNormalizer, list[Any], set[str]],
    ...,
]:
    return (
        (
            "aws",
            AwsNormalizer(),
            _aws_resources(
                [
                    aws_statement("Allow", _AWS_SEND, AWS_QUEUE_ARN),
                    aws_statement("Allow", _AWS_RECEIVE, AWS_QUEUE_ARN),
                    aws_statement("Allow", _AWS_DELETE_MESSAGE, AWS_QUEUE_ARN),
                ]
            ),
            {
                AWS_TAMPERING_RULE,
                AWS_DISCLOSURE_RULE,
                AWS_MESSAGE_DISRUPTION_RULE,
            },
        ),
        (
            "gcp",
            GcpNormalizer(),
            [
                _gcp_workload(),
                gcp_public_invoker(),
                gcp_topic(),
                gcp_subscription(),
                _gcp_custom_role([_GCP_PUBLISH, _GCP_CONSUME]),
                gcp_topic_iam_member(role=_gcp_role_name()),
                gcp_subscription_iam_member(role=_gcp_role_name()),
            ],
            {
                GCP_TAMPERING_RULE,
                GCP_DISCLOSURE_RULE,
                GCP_MESSAGE_DISRUPTION_RULE,
            },
        ),
        (
            "azure",
            AzureNormalizer(),
            [
                azure_namespace(),
                azure_entity(
                    AzureResourceType.SERVICE_BUS_QUEUE,
                    AZURE_QUEUE_ID,
                ),
                _azure_workload(),
                _azure_control_role(
                    actions=[],
                    data_actions=[_AZURE_SEND, _AZURE_RECEIVE],
                ),
                _azure_control_assignment(),
            ],
            {
                AZURE_TAMPERING_RULE,
                AZURE_DISCLOSURE_RULE,
                AZURE_MESSAGE_DISRUPTION_RULE,
            },
        ),
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


class PublicWorkloadMessagingTopologyDisruptionParityTests(unittest.TestCase):
    """Pin shared topology DoS outcomes without flattening provider evidence."""

    def test_provider_local_topology_rules_are_registered(self) -> None:
        self.assertIn(
            AWS_TOPOLOGY_DISRUPTION_RULE,
            _flatten(AWS_RULE_GROUP_IDS),
        )
        self.assertIn(
            GCP_TOPOLOGY_DISRUPTION_RULE,
            _flatten(GCP_RULE_GROUP_IDS),
        )
        self.assertIn(
            AZURE_TOPOLOGY_DISRUPTION_RULE,
            _flatten(AZURE_RULE_GROUP_IDS),
        )

    def test_topology_deletion_emits_only_provider_local_denial_of_service(
        self,
    ) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_topology_resources(),
                AWS_TOPOLOGY_DISRUPTION_RULE,
                2,
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_topology_resources(),
                GCP_TOPOLOGY_DISRUPTION_RULE,
                2,
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_topology_resources(),
                AZURE_TOPOLOGY_DISRUPTION_RULE,
                4,
            ),
        )

        for provider, normalizer, resources, rule_id, path_count in cases:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                paths, uncertainties = _topology_state(provider, inventory)

                self.assertEqual(len(paths), path_count)
                self.assertEqual(uncertainties, [])
                self.assertEqual(
                    [finding.rule_id for finding in findings],
                    [rule_id],
                )
                self.assertEqual(
                    findings[0].category,
                    StrideCategory.DENIAL_OF_SERVICE,
                )
                self.assertEqual(
                    len(findings[0].affected_resources),
                    len(set(findings[0].affected_resources)),
                )

    def test_send_receive_and_message_removal_do_not_become_topology_disruption(
        self,
    ) -> None:
        topology_rules = {
            "aws": AWS_TOPOLOGY_DISRUPTION_RULE,
            "gcp": GCP_TOPOLOGY_DISRUPTION_RULE,
            "azure": AZURE_TOPOLOGY_DISRUPTION_RULE,
        }
        for provider, normalizer, resources, expected_rules in _non_topology_resources():
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                paths, _uncertainties = _topology_state(provider, inventory)

                self.assertEqual(paths, [])
                self.assertEqual(
                    {finding.rule_id for finding in findings},
                    expected_rules,
                )
                self.assertNotIn(
                    topology_rules[provider],
                    {finding.rule_id for finding in findings},
                )
                self.assertEqual(
                    {finding.category for finding in findings},
                    {
                        StrideCategory.TAMPERING,
                        StrideCategory.INFORMATION_DISCLOSURE,
                        StrideCategory.DENIAL_OF_SERVICE,
                    },
                )

    def test_native_target_granularity_and_ancestry_remain_provider_specific(
        self,
    ) -> None:
        aws_inventory, aws_findings = _analyze(
            AwsNormalizer(),
            _aws_topology_resources(),
        )
        aws_paths, _ = _topology_state("aws", aws_inventory)
        aws_by_operation = {path["operation"]: path for path in aws_paths}
        self.assertEqual(
            aws_by_operation[_AWS_DELETE_QUEUE]["target_scope"],
            "exact_sqs_queue",
        )
        self.assertEqual(
            aws_by_operation[_AWS_DELETE_QUEUE]["target_model_evidence_addresses"],
            ["aws_sqs_queue.orders"],
        )
        self.assertEqual(
            aws_by_operation[_AWS_DELETE_TOPIC]["target_scope"],
            "exact_sns_topic",
        )
        self.assertEqual(
            aws_by_operation[_AWS_DELETE_TOPIC]["target_model_evidence_addresses"],
            ["aws_sns_topic.orders"],
        )
        self.assertTrue(
            all(path["same_account"] is True for path in aws_paths),
        )
        self.assertEqual(
            _finding_by_rule(
                aws_findings,
                AWS_TOPOLOGY_DISRUPTION_RULE,
            ).severity_reasoning.blast_radius,
            2,
        )

        topic, subscription = _cross_project_topic_and_subscription()
        gcp_inventory, gcp_findings = _analyze(
            GcpNormalizer(),
            [
                _gcp_workload(),
                gcp_public_invoker(),
                topic,
                subscription,
                gcp_project_iam_member(
                    project="producer-project",
                    role="roles/pubsub.admin",
                    name="producer_admin",
                ),
                gcp_project_iam_member(
                    project="consumer-project",
                    role="roles/pubsub.admin",
                    name="consumer_admin",
                ),
            ],
        )
        gcp_paths, _ = _topology_state("gcp", gcp_inventory)
        gcp_by_kind = {path["messaging_resource_kind"]: path for path in gcp_paths}
        self.assertEqual(
            gcp_by_kind["topic"]["target_model_evidence_addresses"],
            [GCP_TOPIC_ADDRESS],
        )
        self.assertEqual(
            gcp_by_kind["topic"]["scope"],
            "producer-project",
        )
        self.assertEqual(
            gcp_by_kind["subscription"]["target_model_evidence_addresses"],
            [GCP_TOPIC_ADDRESS, GCP_SUBSCRIPTION_ADDRESS],
        )
        self.assertEqual(
            gcp_by_kind["subscription"]["subscription_project"],
            "consumer-project",
        )
        self.assertEqual(
            gcp_by_kind["subscription"]["topic_project"],
            "producer-project",
        )
        self.assertEqual(
            _finding_by_rule(
                gcp_findings,
                GCP_TOPOLOGY_DISRUPTION_RULE,
            ).severity_reasoning.blast_radius,
            2,
        )

        azure_inventory, azure_findings = _analyze(
            AzureNormalizer(),
            _azure_topology_resources(),
        )
        azure_paths, _ = _topology_state("azure", azure_inventory)
        azure_by_kind = {path["service_bus_resource_kind"]: path for path in azure_paths}
        self.assertEqual(
            azure_by_kind["namespace"]["target_model_evidence_addresses"],
            ["azurerm_servicebus_namespace.orders"],
        )
        self.assertEqual(
            azure_by_kind["queue"]["target_model_evidence_addresses"],
            [
                "azurerm_servicebus_namespace.orders",
                "azurerm_servicebus_queue.orders",
            ],
        )
        self.assertEqual(
            azure_by_kind["topic"]["target_model_evidence_addresses"],
            [
                "azurerm_servicebus_namespace.orders",
                "azurerm_servicebus_topic.orders",
            ],
        )
        self.assertEqual(
            azure_by_kind["subscription"]["target_model_evidence_addresses"],
            [
                "azurerm_servicebus_namespace.orders",
                "azurerm_servicebus_topic.orders",
                "azurerm_servicebus_subscription.orders",
            ],
        )
        self.assertEqual(
            {path["authorization_grant"]["assignment_scope_arm_id"] for path in azure_paths},
            {AZURE_NAMESPACE_ID},
        )
        self.assertEqual(
            _finding_by_rule(
                azure_findings,
                AZURE_TOPOLOGY_DISRUPTION_RULE,
            ).severity_reasoning.blast_radius,
            2,
        )

        for provider, paths in (
            ("aws", aws_paths),
            ("gcp", gcp_paths),
            ("azure", azure_paths),
        ):
            fingerprints = [_topology_fingerprint(provider, path) for path in paths]
            self.assertEqual(len(fingerprints), len(set(fingerprints)))

    def test_private_workloads_keep_topology_paths_without_public_findings(
        self,
    ) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_topology_resources(
                    public=False,
                    include_topic=False,
                ),
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_topology_resources(
                    public=False,
                    include_subscription=False,
                ),
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_topology_resources(
                    public=False,
                    operations=(_AZURE_DELETE_QUEUE,),
                ),
            ),
        )

        for provider, normalizer, resources in cases:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                paths, uncertainties = _topology_state(provider, inventory)

                self.assertTrue(paths)
                self.assertEqual(uncertainties, [])
                self.assertEqual(findings, [])

    def test_conditional_incomplete_ambiguous_or_incompatible_authority_fails_closed(
        self,
    ) -> None:
        cases = (
            (
                "aws-conditional",
                "aws",
                AwsNormalizer(),
                _aws_resources(
                    [
                        aws_statement(
                            "Allow",
                            _AWS_DELETE_QUEUE,
                            AWS_QUEUE_ARN,
                            condition={
                                "StringEquals": {
                                    "aws:RequestedRegion": "us-east-1",
                                }
                            },
                        )
                    ]
                ),
            ),
            (
                "aws-incomplete",
                "aws",
                AwsNormalizer(),
                _aws_resources(
                    [
                        aws_statement(
                            "Allow",
                            _AWS_DELETE_QUEUE,
                            AWS_QUEUE_ARN,
                        )
                    ],
                    incomplete=True,
                ),
            ),
            (
                "gcp-conditional",
                "gcp",
                GcpNormalizer(),
                [
                    _gcp_workload(),
                    gcp_public_invoker(),
                    gcp_topic(),
                    _gcp_custom_role([_GCP_DELETE_TOPIC]),
                    gcp_topic_iam_member(
                        role=_gcp_role_name(),
                        condition={
                            "title": "runtime-window",
                            "expression": ('request.time < timestamp("2030-01-01T00:00:00Z")'),
                        },
                    ),
                ],
            ),
            (
                "gcp-manager-ambiguity",
                "gcp",
                GcpNormalizer(),
                [
                    _gcp_workload(),
                    gcp_public_invoker(),
                    gcp_topic(),
                    gcp_subscription(),
                    _gcp_custom_role([_GCP_DELETE_SUBSCRIPTION]),
                    gcp_subscription_iam_member(
                        role=("google_project_iam_custom_role.messaging_topology.name"),
                    ),
                    gcp_subscription_iam_binding(
                        role=_gcp_role_name(),
                        members=["serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"],
                    ),
                ],
            ),
            (
                "azure-unknown-condition-version",
                "azure",
                AzureNormalizer(),
                [
                    azure_namespace(),
                    azure_entity(
                        AzureResourceType.SERVICE_BUS_QUEUE,
                        AZURE_QUEUE_ID,
                    ),
                    _azure_workload(),
                    _azure_control_role(actions=[_AZURE_DELETE_QUEUE]),
                    _azure_control_assignment(
                        scope=AZURE_QUEUE_ID,
                        unknown_values={"condition_version": True},
                    ),
                ],
            ),
            (
                "azure-incompatible-assignable-scope",
                "azure",
                AzureNormalizer(),
                [
                    azure_namespace(),
                    azure_entity(
                        AzureResourceType.SERVICE_BUS_QUEUE,
                        AZURE_QUEUE_ID,
                    ),
                    _azure_workload(),
                    _azure_control_role(
                        actions=[_AZURE_DELETE_QUEUE],
                        assignable_scopes=["/subscriptions/other-subscription"],
                    ),
                    _azure_control_assignment(
                        scope=AZURE_QUEUE_ID,
                    ),
                ],
            ),
        )

        topology_rules = {
            "aws": AWS_TOPOLOGY_DISRUPTION_RULE,
            "gcp": GCP_TOPOLOGY_DISRUPTION_RULE,
            "azure": AZURE_TOPOLOGY_DISRUPTION_RULE,
        }
        for label, provider, normalizer, resources in cases:
            with self.subTest(case=label):
                inventory, findings = _analyze(normalizer, resources)
                paths, uncertainties = _topology_state(provider, inventory)

                self.assertEqual(paths, [])
                self.assertTrue(uncertainties)
                self.assertNotIn(
                    topology_rules[provider],
                    {finding.rule_id for finding in findings},
                )

    def test_outcome_and_lock_evidence_do_not_claim_deletion_or_recovery(
        self,
    ) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_topology_resources(include_topic=False),
                AWS_TOPOLOGY_DISRUPTION_RULE,
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_topology_resources(include_subscription=False),
                GCP_TOPOLOGY_DISRUPTION_RULE,
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_topology_resources(
                    operations=(_AZURE_DELETE_QUEUE,),
                ),
                AZURE_TOPOLOGY_DISRUPTION_RULE,
            ),
        )

        for provider, normalizer, resources, rule_id in cases:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                paths, _uncertainties = _topology_state(provider, inventory)
                finding = _finding_by_rule(findings, rule_id)

                self.assertEqual(len(paths), 1)
                outcome = paths[0]["outcome_evidence"]
                assert isinstance(outcome, Mapping)
                self.assertIs(
                    outcome["successful_deletion_observed"],
                    False,
                )
                self.assertIn(
                    "not_established_by_modeled_",
                    str(outcome["recovery_state"]),
                )
                self.assertIs(
                    outcome["out_of_plan_topology_evaluated"],
                    False,
                )
                if provider in {"aws", "gcp"}:
                    self.assertIs(
                        outcome["descendant_impact_evaluated"],
                        False,
                    )
                else:
                    self.assertTrue(
                        any("descendant-resource impact" in value for value in _evidence(finding)["assessment_scope"])
                    )
                    lock_evidence = paths[0]["management_lock_evidence"]
                    assert isinstance(lock_evidence, Mapping)
                    self.assertEqual(
                        lock_evidence["modeled_management_lock_state"],
                        "not_observed",
                    )
                    self.assertIs(
                        lock_evidence["external_management_locks_evaluated"],
                        False,
                    )
                self.assertIn(
                    "does not establish successful deletion",
                    finding.rationale,
                )

        locked_resources = _azure_topology_resources(
            operations=(_AZURE_DELETE_QUEUE,),
        )
        locked_resources.append(
            azure_management_lock(
                scope="azurerm_servicebus_namespace.orders.id",
            )
        )
        locked_inventory, locked_findings = _analyze(
            AzureNormalizer(),
            locked_resources,
        )
        locked_paths, locked_uncertainties = _topology_state(
            "azure",
            locked_inventory,
        )
        self.assertEqual(locked_paths, [])
        self.assertEqual(locked_uncertainties, [])
        self.assertNotIn(
            AZURE_TOPOLOGY_DISRUPTION_RULE,
            {finding.rule_id for finding in locked_findings},
        )

    def test_duplicate_cached_paths_do_not_duplicate_finding_targets_or_evidence(
        self,
    ) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_topology_resources(include_topic=False),
                AWS_TOPOLOGY_DISRUPTION_RULE,
                "aws_sqs_queue.orders",
                "messaging_topology_destruction_paths",
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_topology_resources(include_subscription=False),
                GCP_TOPOLOGY_DISRUPTION_RULE,
                GCP_TOPIC_ADDRESS,
                "pubsub_topology_destruction_paths",
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_topology_resources(
                    operations=(_AZURE_DELETE_QUEUE,),
                ),
                AZURE_TOPOLOGY_DISRUPTION_RULE,
                "azurerm_servicebus_queue.orders",
                "service_bus_topology_destruction_paths",
            ),
        )

        for (
            provider,
            normalizer,
            resources,
            rule_id,
            target_address,
            evidence_key,
        ) in cases:
            with self.subTest(provider=provider):
                inventory, _findings = _analyze(normalizer, resources)
                paths, _uncertainties = _topology_state(provider, inventory)
                self.assertEqual(len(paths), 1)
                _replace_topology_paths(
                    provider,
                    inventory,
                    [*paths, dict(paths[0])],
                )
                injected_paths, _ = _topology_state(provider, inventory)
                self.assertEqual(len(injected_paths), 2)

                findings = _evaluate_inventory(inventory)
                finding = _finding_by_rule(findings, rule_id)
                self.assertEqual(
                    finding.affected_resources.count(target_address),
                    1,
                )
                self.assertEqual(
                    len(_evidence(finding)[evidence_key]),
                    1,
                )
                self.assertEqual(
                    finding.severity_reasoning.blast_radius,
                    1,
                )

    def test_stale_projected_target_evidence_is_rejected_for_every_provider(
        self,
    ) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_topology_resources(include_topic=False),
                AWS_TOPOLOGY_DISRUPTION_RULE,
                "messaging_resource_arn",
                "arn:aws:sqs:us-east-1:111122223333:stale",
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_topology_resources(include_subscription=False),
                GCP_TOPOLOGY_DISRUPTION_RULE,
                "messaging_resource_name",
                "stale-topic",
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_topology_resources(
                    operations=(_AZURE_DELETE_QUEUE,),
                ),
                AZURE_TOPOLOGY_DISRUPTION_RULE,
                "service_bus_resource_id",
                f"{AZURE_QUEUE_ID}/stale",
            ),
        )

        for (
            provider,
            normalizer,
            resources,
            rule_id,
            field,
            stale_value,
        ) in cases:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                self.assertIsNotNone(_finding_by_rule(findings, rule_id))
                paths, _uncertainties = _topology_state(provider, inventory)
                self.assertEqual(len(paths), 1)
                stale_paths = [dict(path) for path in paths]
                stale_paths[0][field] = stale_value
                _replace_topology_paths(provider, inventory, stale_paths)

                stale_findings = _evaluate_inventory(inventory)
                self.assertNotIn(
                    rule_id,
                    {finding.rule_id for finding in stale_findings},
                )

    def test_reused_rule_engine_preserves_provider_isolation_and_payload_exclusion(
        self,
    ) -> None:
        aws_resources = _aws_topology_resources(include_topic=False)
        aws_queue_resource = next(
            resource for resource in aws_resources if getattr(resource, "address", None) == "aws_sqs_queue.orders"
        )
        aws_queue_resource.values["tags"] = {
            "payload": "aws-topology-payload-must-not-leak",
        }

        gcp_resources = _gcp_topology_resources(include_subscription=False)
        gcp_topic_resource = next(
            resource for resource in gcp_resources if getattr(resource, "address", None) == GCP_TOPIC_ADDRESS
        )
        gcp_topic_resource.values["labels"] = {
            "payload": "gcp-topology-payload-must-not-leak",
        }

        azure_resources = _azure_topology_resources(
            operations=(_AZURE_DELETE_QUEUE,),
        )
        azure_queue_resource = next(
            resource
            for resource in azure_resources
            if getattr(resource, "address", None) == "azurerm_servicebus_queue.orders"
        )
        azure_queue_resource.values["tags"] = {
            "payload": "azure-topology-payload-must-not-leak",
        }

        cases = (
            (
                "aws",
                AwsNormalizer(),
                aws_resources,
                AWS_TOPOLOGY_DISRUPTION_RULE,
                ("google_", "azurerm_", "Microsoft.ServiceBus"),
                "aws-topology-payload-must-not-leak",
            ),
            (
                "gcp",
                GcpNormalizer(),
                gcp_resources,
                GCP_TOPOLOGY_DISRUPTION_RULE,
                ("aws_", "azurerm_", "Microsoft.ServiceBus"),
                "gcp-topology-payload-must-not-leak",
            ),
            (
                "azure",
                AzureNormalizer(),
                azure_resources,
                AZURE_TOPOLOGY_DISRUPTION_RULE,
                ("aws_", "google_", "pubsub."),
                "azure-topology-payload-must-not-leak",
            ),
            (
                "aws-second-pass",
                AwsNormalizer(),
                aws_resources,
                AWS_TOPOLOGY_DISRUPTION_RULE,
                ("google_", "azurerm_", "Microsoft.ServiceBus"),
                "aws-topology-payload-must-not-leak",
            ),
        )
        engine = StrideRuleEngine()

        for (
            label,
            normalizer,
            resources,
            rule_id,
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
                paths, uncertainties = _topology_state(provider, inventory)
                local_findings = [finding for finding in findings if finding.rule_id == rule_id]

                self.assertTrue(paths)
                self.assertEqual(uncertainties, [])
                self.assertEqual(len(local_findings), 1)
                self.assertEqual(
                    [finding.rule_id for finding in findings],
                    [rule_id],
                )
                payload = json.dumps(
                    {
                        "paths": paths,
                        "findings": _finding_payload(findings),
                    },
                    sort_keys=True,
                )
                self.assertNotIn(sentinel, payload)
                for prefix in foreign_prefixes:
                    self.assertNotIn(prefix, payload)


if __name__ == "__main__":
    unittest.main()
