from __future__ import annotations

import unittest

from tests.providers.gcp.test_gcp_cloud_run_pubsub_access_paths import (
    _PROJECT,
    _SUBSCRIPTION_ADDRESS,
    _custom_role,
    _subscription,
    _subscription_iam_member,
    _topic,
)
from tests.providers.gcp.test_gcp_cloud_run_pubsub_message_removal_paths import (
    _organization_custom_role,
    _project_iam_member,
    _project_resource,
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

_RULE_ID = "gcp-public-cloud-run-pubsub-message-disruption"
_CONSUME_RULE_ID = "gcp-public-cloud-run-pubsub-consume-access"
_MUTATION_RULE_ID = "gcp-public-cloud-run-pubsub-mutation-access"
_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.orders"
_SUBSCRIPTION_IAM_ADDRESS = "google_pubsub_subscription_iam_member.orders_access"
_ACKNOWLEDGE = "pubsub.subscriptions.consume"


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = GcpNormalizer().normalize(resources)
    findings = StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or {_RULE_ID})),
    )
    return inventory, findings


def _evidence(finding):
    return {item.key: item.values for item in finding.evidence}


class GcpPublicCloudRunPubsubMessageDisruptionRuleTests(unittest.TestCase):
    def test_rule_is_registered(self) -> None:
        registered = {rule_id for group in GCP_RULE_GROUP_IDS for rule_id in group}
        self.assertIn(_RULE_ID, registered)

    def test_acknowledgement_authority_is_disruption_not_mutation(self) -> None:
        _, findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _topic(),
                _subscription(),
                _subscription_iam_member(),
            ],
            _RULE_ID,
            _CONSUME_RULE_ID,
            _MUTATION_RULE_ID,
        )

        self.assertEqual(
            {finding.rule_id for finding in findings},
            {_RULE_ID, _CONSUME_RULE_ID},
        )
        disruption = next(finding for finding in findings if finding.rule_id == _RULE_ID)
        self.assertEqual(disruption.category, StrideCategory.DENIAL_OF_SERVICE)
        self.assertEqual(
            disruption.affected_resources,
            [
                _WORKLOAD_ADDRESS,
                _PUBLIC_INVOKER_ADDRESS,
                _SUBSCRIPTION_ADDRESS,
                _SUBSCRIPTION_IAM_ADDRESS,
            ],
        )
        self.assertIn("acknowledge delivered messages", disruption.rationale)
        self.assertIn("successful acknowledgement", disruption.rationale)
        evidence = _evidence(disruption)
        path = evidence["pubsub_message_removal_paths"][0]
        self.assertIn(f"operation={_ACKNOWLEDGE}", path)
        self.assertIn("target_granularity=subscription_message_namespace", path)
        self.assertIn("authorization_state=granted", path)
        self.assertIn("successful_acknowledgement_not_established=true", evidence["delivery_and_recovery_evidence"][0])

    def test_unknown_replay_posture_does_not_suppress_disruption(self) -> None:
        subscription = _subscription()
        subscription.values["message_retention_duration"] = "86400s"
        subscription.unknown_values["retain_acked_messages"] = True

        _, findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _topic(),
                subscription,
                _subscription_iam_member(),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = _evidence(findings[0])
        self.assertIn(
            "acknowledged_message_replay_state=unknown",
            evidence["delivery_and_recovery_evidence"][0],
        )
        self.assertIn("Replay posture is partly unknown", findings[0].rationale)
        self.assertTrue(evidence["pubsub_message_removal_path_uncertainties"])

    def test_project_acknowledgement_grant_fans_out_and_counts_unique_subscriptions(self) -> None:
        archive = _subscription(
            "google_pubsub_subscription.archive",
            name="archive",
            reference=f"projects/{_PROJECT}/subscriptions/archive-worker",
        )

        _, findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _topic(),
                _subscription(),
                archive,
                _project_iam_member(),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity_reasoning.blast_radius, 2)
        self.assertEqual(
            finding.affected_resources,
            [
                _WORKLOAD_ADDRESS,
                _PUBLIC_INVOKER_ADDRESS,
                "google_pubsub_subscription.archive",
                _SUBSCRIPTION_ADDRESS,
                "google_project_iam_member.project_subscriber",
            ],
        )
        self.assertEqual(len(_evidence(finding)["pubsub_message_removal_paths"]), 2)

    def test_stale_custom_role_without_acknowledgement_permission_is_rejected(self) -> None:
        role_name = f"projects/{_PROJECT}/roles/cloudRunMessaging"
        resources = [
            _public_cloud_run(),
            _public_invoker(),
            _topic(),
            _subscription(),
            _custom_role(permissions=[_ACKNOWLEDGE]),
            _subscription_iam_member(role=role_name),
        ]
        inventory, findings = _evaluate(resources)
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        role = inventory.get_by_address("google_project_iam_custom_role.cloud_run_messaging")
        assert workload is not None
        assert role is not None
        paths = gcp_facts(workload).cloud_run_pubsub_message_removal_paths
        paths[0]["custom_role_permissions"] = []
        gcp_facts(workload).set_cloud_run_pubsub_message_removal_paths(paths)
        gcp_facts(role).set(GcpResourceMetadata.CUSTOM_ROLE_PERMISSIONS, [])

        self.assertEqual(
            StrideRuleEngine().evaluate(
                inventory,
                detect_trust_boundaries(inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
            ),
            [],
        )

    def test_stale_organization_role_project_ancestry_is_rejected(self) -> None:
        role = _organization_custom_role(organization_id="123456")
        resources = [
            _public_cloud_run(),
            _public_invoker(),
            _topic(),
            _subscription(),
            _project_resource(project=_PROJECT, organization_id="123456"),
            role,
            _subscription_iam_member(role="organizations/123456/roles/pubsubAck"),
        ]
        inventory, findings = _evaluate(resources)
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        project = inventory.get_by_address(f"google_project.{_PROJECT}")
        assert project is not None
        gcp_facts(project).set(GcpResourceMetadata.ORGANIZATION_ID, "654321")

        self.assertEqual(
            StrideRuleEngine().evaluate(
                inventory,
                detect_trust_boundaries(inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
            ),
            [],
        )

    def test_stale_project_role_ownership_is_rejected(self) -> None:
        role = _custom_role(permissions=[_ACKNOWLEDGE])
        resources = [
            _public_cloud_run(),
            _public_invoker(),
            _topic(),
            _subscription(),
            role,
            _subscription_iam_member(role=f"projects/{_PROJECT}/roles/cloudRunMessaging"),
        ]
        inventory, findings = _evaluate(resources)
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        role_resource = inventory.get_by_address("google_project_iam_custom_role.cloud_run_messaging")
        assert role_resource is not None
        gcp_facts(role_resource).set(GcpResourceMetadata.PROJECT, "other-project")

        self.assertEqual(
            StrideRuleEngine().evaluate(
                inventory,
                detect_trust_boundaries(inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
            ),
            [],
        )

    def test_private_workload_keeps_path_but_has_no_public_disruption_finding(self) -> None:
        resources = [
            _public_cloud_run(public_ingress=False),
            _public_invoker(),
            _topic(),
            _subscription(),
            _subscription_iam_member(),
        ]
        inventory, findings = _evaluate(resources)
        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        self.assertTrue(gcp_facts(workload).cloud_run_pubsub_message_removal_paths)
        self.assertEqual(findings, [])

    def test_stale_current_grant_and_delivery_evidence_are_rejected(self) -> None:
        resources = [
            _public_cloud_run(),
            _public_invoker(),
            _topic(),
            _subscription(),
            _subscription_iam_member(),
        ]
        inventory, findings = _evaluate(resources)
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        iam_resource = inventory.get_by_address(_SUBSCRIPTION_IAM_ADDRESS)
        assert workload is not None
        assert iam_resource is not None
        gcp_facts(iam_resource).set(GcpResourceMetadata.IAM_BINDINGS, [])
        gcp_facts(iam_resource).set(GcpResourceMetadata.IAM_ROLE, None)
        gcp_facts(iam_resource).set(GcpResourceMetadata.IAM_MEMBER, None)
        self.assertEqual(
            StrideRuleEngine().evaluate(
                inventory,
                detect_trust_boundaries(inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
            ),
            [],
        )

        inventory, findings = _evaluate(resources)
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        workload_facts = gcp_facts(workload)
        paths = workload_facts.cloud_run_pubsub_message_removal_paths
        paths[0]["delivery_evidence"]["acknowledged_message_replay_state"] = "unknown"
        workload_facts.set_cloud_run_pubsub_message_removal_paths(paths)
        self.assertEqual(
            StrideRuleEngine().evaluate(
                inventory,
                detect_trust_boundaries(inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
