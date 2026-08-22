from __future__ import annotations

import unittest

from tests.providers.gcp.test_gcp_cloud_run_pubsub_access_paths import (
    _PROJECT,
    _SUBSCRIPTION_ADDRESS,
    _TOPIC_ADDRESS,
    _custom_role,
    _subscription,
    _subscription_iam_member,
    _topic,
    _topic_iam_member,
)
from tests.providers.gcp.test_gcp_public_cloud_run_pubsub_consume_rules import (
    _PUBLIC_INVOKER_ADDRESS,
    _public_cloud_run,
    _public_invoker,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import StrideCategory, TerraformResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

_RULE_ID = "gcp-public-cloud-run-pubsub-topology-disruption"
_MUTATION_RULE_ID = "gcp-public-cloud-run-pubsub-mutation-access"
_MESSAGE_DISRUPTION_RULE_ID = "gcp-public-cloud-run-pubsub-message-disruption"
_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.orders"
_TOPIC_IAM_ADDRESS = "google_pubsub_topic_iam_member.orders_access"
_SUBSCRIPTION_IAM_ADDRESS = "google_pubsub_subscription_iam_member.orders_access"
_ROLE_NAME = f"projects/{_PROJECT}/roles/cloudRunMessaging"
_DELETE_TOPIC = "pubsub.topics.delete"
_DELETE_SUBSCRIPTION = "pubsub.subscriptions.delete"


def _evaluate(
    resources: list[TerraformResource],
    *rule_ids: str,
):
    inventory = GcpNormalizer().normalize(resources)
    findings = StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or {_RULE_ID})),
    )
    return inventory, findings


def _evidence(finding):
    return {item.key: item.values for item in finding.evidence}


class GcpPublicCloudRunPubsubTopologyDisruptionRuleTests(unittest.TestCase):
    def test_rule_is_registered(self) -> None:
        registered = {rule_id for group in GCP_RULE_GROUP_IDS for rule_id in group}
        self.assertIn(_RULE_ID, registered)

    def test_topic_and_subscription_deletion_are_topology_dos_only(self) -> None:
        _, findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _topic(),
                _subscription(),
                _custom_role(permissions=[_DELETE_TOPIC, _DELETE_SUBSCRIPTION]),
                _topic_iam_member(role=_ROLE_NAME),
                _subscription_iam_member(role=_ROLE_NAME),
            ],
            _RULE_ID,
            _MUTATION_RULE_ID,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.category, StrideCategory.DENIAL_OF_SERVICE)
        self.assertEqual(
            finding.affected_resources,
            [
                _WORKLOAD_ADDRESS,
                _PUBLIC_INVOKER_ADDRESS,
                _SUBSCRIPTION_ADDRESS,
                _TOPIC_ADDRESS,
                "google_project_iam_custom_role.cloud_run_messaging",
                _SUBSCRIPTION_IAM_ADDRESS,
                _TOPIC_IAM_ADDRESS,
            ],
        )
        evidence = _evidence(finding)
        self.assertEqual(len(evidence["pubsub_topology_destruction_paths"]), 2)
        self.assertEqual(
            {f"operation={operation}" for operation in (_DELETE_TOPIC, _DELETE_SUBSCRIPTION)},
            {
                next(field for field in record.split("; ") if field.startswith("operation="))
                for record in evidence["pubsub_topology_destruction_paths"]
            },
        )
        self.assertTrue(
            all(
                "successful_deletion_observed=False" in record
                and "descendant_impact_evaluated=False" in record
                and "out_of_plan_topology_evaluated=False" in record
                for record in evidence["topology_deletion_outcome_evidence"]
            )
        )
        self.assertIn("does not establish successful deletion", finding.rationale)
        self.assertIn("subscription impact from topic deletion", finding.rationale)

    def test_subscription_deletion_is_not_message_disruption(self) -> None:
        _, findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _topic(),
                _subscription(),
                _custom_role(permissions=[_DELETE_SUBSCRIPTION]),
                _subscription_iam_member(role=_ROLE_NAME),
            ],
            _RULE_ID,
            _MESSAGE_DISRUPTION_RULE_ID,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

    def test_private_workload_keeps_topology_paths_without_public_finding(self) -> None:
        inventory, findings = _evaluate(
            [
                _public_cloud_run(public_ingress=False),
                _public_invoker(),
                _topic(),
                _custom_role(permissions=[_DELETE_TOPIC]),
                _topic_iam_member(role=_ROLE_NAME),
            ]
        )

        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        self.assertTrue(gcp_facts(workload).cloud_run_pubsub_topology_destruction_paths)
        self.assertEqual(findings, [])

    def test_stale_current_iam_binding_suppresses_topology_finding(self) -> None:
        resources = [
            _public_cloud_run(),
            _public_invoker(),
            _topic(),
            _custom_role(permissions=[_DELETE_TOPIC]),
            _topic_iam_member(role=_ROLE_NAME),
        ]
        inventory, findings = _evaluate(resources)
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        iam_resource = inventory.get_by_address(_TOPIC_IAM_ADDRESS)
        assert iam_resource is not None
        gcp_facts(iam_resource).set(GcpResourceMetadata.IAM_BINDINGS, [])
        gcp_facts(iam_resource).set(GcpResourceMetadata.IAM_ROLE, None)
        gcp_facts(iam_resource).set(GcpResourceMetadata.IAM_MEMBER, None)

        _, stale_findings = _evaluate_inventory(inventory)
        self.assertEqual(stale_findings, [])

    def test_stale_copied_target_identity_suppresses_topology_finding(self) -> None:
        resources = [
            _public_cloud_run(),
            _public_invoker(),
            _topic(),
            _custom_role(permissions=[_DELETE_TOPIC]),
            _topic_iam_member(role=_ROLE_NAME),
        ]
        inventory, findings = _evaluate(resources)
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        paths = gcp_facts(workload).cloud_run_pubsub_topology_destruction_paths
        paths[0]["messaging_resource_name"] = "stale-topic-name"
        gcp_facts(workload).set_cloud_run_pubsub_topology_destruction_paths(paths)

        _, stale_findings = _evaluate_inventory(inventory)
        self.assertEqual(stale_findings, [])


def _evaluate_inventory(inventory):
    return inventory, StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )


if __name__ == "__main__":
    unittest.main()
