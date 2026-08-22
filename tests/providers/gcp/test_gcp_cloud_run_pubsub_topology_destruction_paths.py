from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.test_gcp_cloud_run_pubsub_access_paths import (
    _PROJECT,
    _SUBSCRIPTION_ADDRESS,
    _SUBSCRIPTION_REFERENCE,
    _TOPIC_ADDRESS,
    _TOPIC_REFERENCE,
    _cloud_run,
    _subscription,
    _subscription_iam_member,
    _topic,
    _topic_iam_member,
)
from tests.providers.gcp.test_gcp_cloud_run_pubsub_message_removal_paths import (
    _cross_project_topic_and_subscription,
    _project_iam_member,
    _project_resource,
    _subscription_iam_binding,
)
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_DELETE_TOPIC = "pubsub.topics.delete"
_DELETE_SUBSCRIPTION = "pubsub.subscriptions.delete"
_ROLE_ADDRESS = "google_project_iam_custom_role.messaging_topology"
_ROLE_ID = "messagingTopology"
_ROLE_NAME = f"projects/{_PROJECT}/roles/{_ROLE_ID}"
_ROLE_REFERENCE = f"{_ROLE_ADDRESS}.name"


def _topology_custom_role(
    permissions: list[str],
    *,
    project: str = _PROJECT,
    stage: str = "GA",
    deleted: bool | None = False,
    unknown_values: dict[str, object] | None = None,
    address: str = _ROLE_ADDRESS,
    role_id: str = _ROLE_ID,
) -> object:
    values: dict[str, object] = {
        "project": project,
        "role_id": role_id,
        "name": f"projects/{project}/roles/{role_id}",
        "permissions": permissions,
        "stage": stage,
    }
    if deleted is not None:
        values["deleted"] = deleted
    return _terraform_resource(
        address,
        GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
        values,
        unknown_values=unknown_values,
    )


def _organization_topology_role(
    permissions: list[str],
    *,
    organization_id: str = "123456",
) -> object:
    return _terraform_resource(
        "google_organization_iam_custom_role.messaging_topology",
        GcpResourceType.ORGANIZATION_IAM_CUSTOM_ROLE,
        {
            "org_id": organization_id,
            "role_id": _ROLE_ID,
            "name": f"organizations/{organization_id}/roles/{_ROLE_ID}",
            "permissions": permissions,
            "stage": "GA",
            "deleted": False,
        },
    )


def _topic_iam_binding(
    *,
    role: str = _ROLE_NAME,
    members: list[str] | None = None,
    name: str = "orders_binding",
) -> object:
    return _terraform_resource(
        f"google_pubsub_topic_iam_binding.{name}",
        GcpResourceType.PUBSUB_TOPIC_IAM_BINDING,
        {
            "topic": f"{_TOPIC_ADDRESS}.name",
            "role": role,
            "members": members or ["serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"],
        },
    )


def _workload_facts(resources: list[object]):
    inventory = GcpNormalizer().normalize(resources)
    workload = inventory.get_by_address("google_cloud_run_v2_service.orders")
    assert workload is not None
    return workload, gcp_facts(workload)


class GcpCloudRunPubsubTopologyDestructionPathTests(unittest.TestCase):
    def test_exact_custom_role_grants_preserve_operation_and_target_ancestry(self) -> None:
        workload, facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                _subscription(),
                _topology_custom_role([_DELETE_TOPIC, _DELETE_SUBSCRIPTION]),
                _topic_iam_member(role=_ROLE_REFERENCE),
                _subscription_iam_member(role=_ROLE_NAME),
            ]
        )

        self.assertFalse(workload.public_exposure)
        self.assertEqual(len(facts.cloud_run_pubsub_topology_destruction_paths), 2)
        paths = {path["messaging_resource_kind"]: path for path in facts.cloud_run_pubsub_topology_destruction_paths}
        topic_path = paths["topic"]
        self.assertEqual(topic_path["operation"], _DELETE_TOPIC)
        self.assertEqual(topic_path["operation_class"], "topic_deletion")
        self.assertEqual(topic_path["target_scope"], "exact_pubsub_topic")
        self.assertEqual(topic_path["scope_type"], "topic")
        self.assertEqual(topic_path["scope"], _TOPIC_REFERENCE)
        self.assertEqual(topic_path["target_model_evidence_addresses"], [_TOPIC_ADDRESS])
        self.assertIsNone(topic_path["subscription_address"])
        self.assertEqual(
            topic_path["iam_source_addresses"],
            [
                "google_pubsub_topic_iam_member.orders_access",
                _ROLE_ADDRESS,
            ],
        )
        self.assertEqual(
            topic_path["role_evidence"],
            {
                "role_kind": "custom",
                "role_definition_address": _ROLE_ADDRESS,
                "custom_role_permissions": [_DELETE_SUBSCRIPTION, _DELETE_TOPIC],
                "custom_role_stage": "GA",
                "custom_role_deleted": False,
                "custom_role_grant_scope_compatibility_state": "compatible",
            },
        )

        subscription_path = paths["subscription"]
        self.assertEqual(subscription_path["operation"], _DELETE_SUBSCRIPTION)
        self.assertEqual(subscription_path["operation_class"], "subscription_deletion")
        self.assertEqual(
            subscription_path["target_scope"],
            "exact_pubsub_subscription",
        )
        self.assertEqual(subscription_path["scope_type"], "subscription")
        self.assertEqual(subscription_path["scope"], _SUBSCRIPTION_REFERENCE)
        self.assertEqual(subscription_path["topic_address"], _TOPIC_ADDRESS)
        self.assertEqual(
            subscription_path["subscription_address"],
            _SUBSCRIPTION_ADDRESS,
        )
        self.assertEqual(
            subscription_path["target_model_evidence_addresses"],
            [_TOPIC_ADDRESS, _SUBSCRIPTION_ADDRESS],
        )
        self.assertEqual(subscription_path["matched_permissions"], [_DELETE_SUBSCRIPTION])
        self.assertEqual(subscription_path["authorization_state"], "granted")
        self.assertEqual(subscription_path["iam_manager_ambiguity_state"], "not_detected")
        self.assertFalse(subscription_path["outcome_evidence"]["successful_deletion_observed"])
        self.assertFalse(subscription_path["outcome_evidence"]["descendant_impact_evaluated"])
        self.assertFalse(subscription_path["outcome_evidence"]["out_of_plan_topology_evaluated"])

    def test_builtin_editor_and_admin_preserve_provider_role_evidence(self) -> None:
        _, facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                _subscription(),
                _topic_iam_member(role="roles/pubsub.editor"),
                _subscription_iam_member(role="roles/pubsub.admin"),
            ]
        )

        paths = {path["messaging_resource_kind"]: path for path in facts.cloud_run_pubsub_topology_destruction_paths}
        self.assertEqual(paths["topic"]["role_evidence"]["role_kind"], "editor")
        self.assertEqual(
            paths["subscription"]["role_evidence"]["role_kind"],
            "admin",
        )
        self.assertEqual(paths["topic"]["role_evidence"]["custom_role_permissions"], [])
        self.assertIsNone(paths["topic"]["role_evidence"]["role_definition_address"])

    def test_basic_editor_and_owner_apply_only_at_project_scope(self) -> None:
        cases = (
            ("roles/editor", "editor"),
            ("roles/owner", "owner"),
        )
        for role, expected_kind in cases:
            with self.subTest(role=role):
                _, project_facts = _workload_facts(
                    [
                        _cloud_run(),
                        _topic(),
                        _subscription(),
                        _project_iam_member(role=role),
                    ]
                )
                self.assertEqual(
                    len(project_facts.cloud_run_pubsub_topology_destruction_paths),
                    2,
                )
                self.assertEqual(
                    {
                        path["role_evidence"]["role_kind"]
                        for path in project_facts.cloud_run_pubsub_topology_destruction_paths
                    },
                    {expected_kind},
                )

                _, exact_facts = _workload_facts(
                    [
                        _cloud_run(),
                        _topic(),
                        _subscription(),
                        _topic_iam_member(role=role),
                        _subscription_iam_member(role=role),
                    ]
                )
                self.assertEqual(
                    exact_facts.cloud_run_pubsub_topology_destruction_paths,
                    [],
                )

    def test_project_admin_fans_out_only_to_exact_modeled_targets(self) -> None:
        archive_topic = _topic(
            "google_pubsub_topic.archive",
            name="archive-events",
            reference=f"projects/{_PROJECT}/topics/archive-events",
        )
        archive_subscription = _subscription(
            "google_pubsub_subscription.archive",
            name="archive-worker",
            reference=f"projects/{_PROJECT}/subscriptions/archive-worker",
        )
        archive_subscription.values["topic"] = "google_pubsub_topic.archive.id"
        _, facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                _subscription(),
                archive_topic,
                archive_subscription,
                _project_iam_member(role="roles/pubsub.admin"),
            ]
        )

        paths = facts.cloud_run_pubsub_topology_destruction_paths
        self.assertEqual(len(paths), 4)
        self.assertEqual({path["scope_type"] for path in paths}, {"project"})
        self.assertEqual({path["scope"] for path in paths}, {_PROJECT})
        self.assertEqual(
            {path["messaging_resource_address"] for path in paths},
            {
                _TOPIC_ADDRESS,
                _SUBSCRIPTION_ADDRESS,
                "google_pubsub_topic.archive",
                "google_pubsub_subscription.archive",
            },
        )

    def test_cross_project_project_grants_follow_each_target_owner(self) -> None:
        topic, subscription = _cross_project_topic_and_subscription()
        _, facts = _workload_facts(
            [
                _cloud_run(),
                topic,
                subscription,
                _project_iam_member(
                    project="producer-project",
                    role="roles/pubsub.editor",
                    name="producer_editor",
                ),
                _project_iam_member(
                    project="consumer-project",
                    role="roles/pubsub.admin",
                    name="consumer_admin",
                ),
            ]
        )

        self.assertEqual(len(facts.cloud_run_pubsub_topology_destruction_paths), 2)
        paths = {path["messaging_resource_kind"]: path for path in facts.cloud_run_pubsub_topology_destruction_paths}
        self.assertEqual(paths["topic"]["scope"], "producer-project")
        self.assertEqual(paths["topic"]["topic_project"], "producer-project")
        self.assertEqual(paths["subscription"]["scope"], "consumer-project")
        self.assertEqual(
            paths["subscription"]["subscription_project"],
            "consumer-project",
        )
        self.assertEqual(
            paths["subscription"]["topic_project"],
            "producer-project",
        )

    def test_subscription_deletion_is_independent_of_delivery_mode(self) -> None:
        subscription = _subscription()
        subscription.values["push_config"] = [{"push_endpoint": "https://worker.example.test"}]
        _, facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                subscription,
                _subscription_iam_member(role="roles/pubsub.admin"),
            ]
        )

        self.assertEqual(len(facts.cloud_run_pubsub_topology_destruction_paths), 1)
        self.assertEqual(
            facts.cloud_run_pubsub_topology_destruction_paths[0]["operation"],
            _DELETE_SUBSCRIPTION,
        )
        self.assertEqual(facts.cloud_run_pubsub_message_removal_paths, [])

    def test_exact_custom_role_permissions_do_not_cross_targets(self) -> None:
        cases = (
            ("topic", _DELETE_TOPIC),
            ("subscription", _DELETE_SUBSCRIPTION),
        )
        for expected_kind, permission in cases:
            with self.subTest(permission=permission):
                _, facts = _workload_facts(
                    [
                        _cloud_run(),
                        _topic(),
                        _subscription(),
                        _topology_custom_role([permission]),
                        _topic_iam_member(role=_ROLE_NAME),
                        _subscription_iam_member(role=_ROLE_NAME),
                    ]
                )
                self.assertEqual(
                    [
                        (
                            path["messaging_resource_kind"],
                            path["operation"],
                        )
                        for path in facts.cloud_run_pubsub_topology_destruction_paths
                    ],
                    [(expected_kind, permission)],
                )

    def test_custom_role_wildcard_permissions_fail_closed(self) -> None:
        for permission in (
            "pubsub.topics.*",
            "pubsub.subscriptions.*",
            "pubsub.*",
            "*",
        ):
            with self.subTest(permission=permission):
                _, facts = _workload_facts(
                    [
                        _cloud_run(),
                        _topic(),
                        _subscription(),
                        _topology_custom_role([permission]),
                        _topic_iam_member(role=_ROLE_NAME),
                        _subscription_iam_member(role=_ROLE_NAME),
                    ]
                )

                self.assertEqual(
                    facts.cloud_run_pubsub_topology_destruction_paths,
                    [],
                )
                self.assertTrue(
                    any(
                        "unsupported wildcard permission" in uncertainty
                        for uncertainty in facts.cloud_run_pubsub_topology_destruction_path_uncertainties
                    )
                )

    def test_conditions_and_unresolved_subscription_ancestry_fail_closed(self) -> None:
        conditional = _topic_iam_member(
            role=_ROLE_NAME,
            condition={
                "title": "runtime-window",
                "expression": "request.time < timestamp('2030-01-01T00:00:00Z')",
            },
        )
        unresolved_subscription = _subscription()
        unresolved_subscription.values["topic"] = "google_pubsub_topic.missing.id"
        _, facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                unresolved_subscription,
                _topology_custom_role([_DELETE_TOPIC, _DELETE_SUBSCRIPTION]),
                conditional,
                _subscription_iam_member(role=_ROLE_NAME),
            ]
        )

        self.assertEqual(facts.cloud_run_pubsub_topology_destruction_paths, [])
        self.assertTrue(
            any(
                "condition is not deterministic" in uncertainty
                for uncertainty in facts.cloud_run_pubsub_topology_destruction_path_uncertainties
            )
        )
        self.assertTrue(
            any(
                "unresolved topic ancestry" in uncertainty
                for uncertainty in facts.cloud_run_pubsub_topology_destruction_path_uncertainties
            )
        )

    def test_unsupported_symbolic_target_attributes_do_not_resolve(self) -> None:
        invalid_topic_scope = _topic_iam_member(
            role="roles/pubsub.admin",
            topic=f"{_TOPIC_ADDRESS}.secret_id",
        )
        _, topic_facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                invalid_topic_scope,
            ]
        )
        self.assertEqual(
            topic_facts.cloud_run_pubsub_topology_destruction_paths,
            [],
        )
        self.assertTrue(topic_facts.cloud_run_pubsub_topology_destruction_path_uncertainties)

        invalid_subscription = _subscription()
        invalid_subscription.values["topic"] = f"{_TOPIC_ADDRESS}.secret_id"
        _, subscription_facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                invalid_subscription,
                _subscription_iam_member(role="roles/pubsub.admin"),
            ]
        )
        self.assertEqual(
            subscription_facts.cloud_run_pubsub_topology_destruction_paths,
            [],
        )
        self.assertTrue(
            any(
                "unresolved topic ancestry" in uncertainty
                for uncertainty in subscription_facts.cloud_run_pubsub_topology_destruction_path_uncertainties
            )
        )

    def test_plan_unknown_native_target_identity_fails_closed(self) -> None:
        unknown_topic = _topic()
        unknown_topic.unknown_values["name"] = True
        _, topic_facts = _workload_facts(
            [
                _cloud_run(),
                unknown_topic,
                _topic_iam_member(role="roles/pubsub.admin"),
            ]
        )
        self.assertEqual(
            topic_facts.cloud_run_pubsub_topology_destruction_paths,
            [],
        )
        self.assertTrue(
            any(
                "unresolved native identity" in uncertainty
                for uncertainty in topic_facts.cloud_run_pubsub_topology_destruction_path_uncertainties
            )
        )

        unknown_subscription = _subscription()
        unknown_subscription.unknown_values["project"] = True
        _, subscription_facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                unknown_subscription,
                _subscription_iam_member(role="roles/pubsub.admin"),
            ]
        )
        self.assertEqual(
            subscription_facts.cloud_run_pubsub_topology_destruction_paths,
            [],
        )
        self.assertTrue(
            any(
                "unresolved native identity" in uncertainty
                for uncertainty in subscription_facts.cloud_run_pubsub_topology_destruction_path_uncertainties
            )
        )

    def test_custom_role_lifecycle_and_permission_uncertainty_fail_closed(self) -> None:
        cases = (
            (
                "disabled",
                _topology_custom_role([_DELETE_TOPIC], stage="DISABLED"),
                False,
            ),
            (
                "deleted",
                _topology_custom_role([_DELETE_TOPIC], deleted=True),
                False,
            ),
            (
                "unknown deleted",
                _topology_custom_role(
                    [_DELETE_TOPIC],
                    deleted=None,
                    unknown_values={"deleted": True},
                ),
                True,
            ),
            (
                "unknown permissions",
                _topology_custom_role(
                    [_DELETE_TOPIC],
                    unknown_values={"permissions": True},
                ),
                True,
            ),
        )
        for case, role, expect_uncertainty in cases:
            with self.subTest(case=case):
                _, facts = _workload_facts(
                    [
                        _cloud_run(),
                        _topic(),
                        role,
                        _topic_iam_member(role=_ROLE_NAME),
                    ]
                )
                self.assertEqual(
                    facts.cloud_run_pubsub_topology_destruction_paths,
                    [],
                )
                if expect_uncertainty:
                    self.assertTrue(facts.cloud_run_pubsub_topology_destruction_path_uncertainties)

    def test_custom_role_aliases_are_reconciled_across_iam_managers(self) -> None:
        _, facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                _subscription(),
                _topology_custom_role([_DELETE_TOPIC, _DELETE_SUBSCRIPTION]),
                _topic_iam_member(role=_ROLE_REFERENCE),
                _topic_iam_binding(role=_ROLE_NAME),
                _subscription_iam_member(role=_ROLE_REFERENCE),
                _subscription_iam_binding(role=_ROLE_NAME),
            ]
        )

        self.assertEqual(facts.cloud_run_pubsub_topology_destruction_paths, [])
        self.assertTrue(
            any(
                "ambiguous" in uncertainty
                for uncertainty in facts.cloud_run_pubsub_topology_destruction_path_uncertainties
            )
        )

    def test_unresolved_authoritative_role_suppresses_additive_path(self) -> None:
        binding = _topic_iam_binding(role=_ROLE_NAME)
        binding.unknown_values["role"] = True
        _, facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                _topology_custom_role([_DELETE_TOPIC]),
                _topic_iam_member(role=_ROLE_NAME),
                binding,
            ]
        )

        self.assertEqual(facts.cloud_run_pubsub_topology_destruction_paths, [])
        self.assertTrue(
            any(
                "may be an overlapping authoritative IAM manager" in uncertainty
                for uncertainty in facts.cloud_run_pubsub_topology_destruction_path_uncertainties
            )
        )

    def test_cross_project_custom_role_must_be_grantable_in_target_project(self) -> None:
        topic, subscription = _cross_project_topic_and_subscription()
        role_name = "projects/producer-project/roles/messagingTopology"
        _, facts = _workload_facts(
            [
                _cloud_run(),
                topic,
                subscription,
                _topology_custom_role(
                    [_DELETE_SUBSCRIPTION],
                    project="producer-project",
                ),
                _subscription_iam_member(role=role_name),
            ]
        )

        self.assertEqual(facts.cloud_run_pubsub_topology_destruction_paths, [])
        self.assertTrue(
            any(
                "not grantable in target project consumer-project" in uncertainty
                for uncertainty in facts.cloud_run_pubsub_topology_destruction_path_uncertainties
            )
        )

    def test_organization_custom_role_requires_exact_project_ancestry(self) -> None:
        role_name = f"organizations/123456/roles/{_ROLE_ID}"
        base = [
            _cloud_run(),
            _topic(),
            _organization_topology_role([_DELETE_TOPIC]),
            _topic_iam_member(role=role_name),
        ]
        _, unresolved = _workload_facts(base)
        self.assertEqual(
            unresolved.cloud_run_pubsub_topology_destruction_paths,
            [],
        )
        self.assertTrue(
            any(
                "grant scope compatibility is unresolved" in uncertainty
                for uncertainty in unresolved.cloud_run_pubsub_topology_destruction_path_uncertainties
            )
        )

        _, compatible = _workload_facts(
            [
                *base,
                _project_resource(project=_PROJECT, organization_id="123456"),
            ]
        )
        self.assertEqual(
            len(compatible.cloud_run_pubsub_topology_destruction_paths),
            1,
        )
        self.assertEqual(
            compatible.cloud_run_pubsub_topology_destruction_paths[0]["role_evidence"][
                "custom_role_grant_scope_compatibility_state"
            ],
            "compatible",
        )

    def test_unresolved_runtime_identity_fails_closed_with_uncertainty(self) -> None:
        _, facts = _workload_facts(
            [
                _cloud_run(service_account=None),
                _topic(),
                _topic_iam_member(role="roles/pubsub.admin"),
            ]
        )

        self.assertEqual(facts.cloud_run_pubsub_topology_destruction_paths, [])
        self.assertTrue(
            any(
                "service account is unresolved" in uncertainty
                for uncertainty in facts.cloud_run_pubsub_topology_destruction_path_uncertainties
            )
        )
