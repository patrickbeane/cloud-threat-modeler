from __future__ import annotations

import unittest
from collections.abc import Sequence

from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _database,
    _project_iam_member,
)
from tests.providers.gcp.test_gcp_cloud_run_gcs_access_paths import (
    _bucket,
    _bucket_iam_member,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import (
    _PUBLIC_INVOKER_ADDRESS,
    _public_cloud_run,
    _public_invoker,
)
from tests.providers.gcp.test_gcp_public_cloud_run_gcs_mutation_rules import (
    _cloud_run as _gcs_cloud_run,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import Finding, NormalizedResource, ResourceInventory, TerraformResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts

_FIRESTORE_RULE_IDS = frozenset(
    {
        "gcp-public-cloud-run-firestore-mutation-access",
        "gcp-public-cloud-run-firestore-entity-disruption",
        "gcp-public-cloud-run-firestore-read-access",
    }
)
_GCS_RULE_IDS = frozenset(
    {
        "gcp-public-cloud-run-gcs-mutation-access",
        "gcp-public-cloud-run-gcs-object-disruption",
    }
)


def _as_resource(value: object) -> TerraformResource:
    assert isinstance(value, TerraformResource)
    return value


def _evaluate_inventory(
    inventory: ResourceInventory,
    rule_ids: frozenset[str],
) -> list[Finding]:
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=rule_ids),
    )


def _current_inventory(
    inventory: ResourceInventory,
    resources: Sequence[NormalizedResource],
) -> ResourceInventory:
    return ResourceInventory(
        provider=inventory.provider,
        resources=resources,
        unsupported_resources=list(inventory.unsupported_resources),
        plan_time_unknown_resources=inventory.plan_time_unknown_resources,
    )


def _firestore_inventory() -> ResourceInventory:
    return GcpNormalizer().normalize(
        [
            _public_cloud_run(),
            _public_invoker(),
            _as_resource(_database()),
            _as_resource(_project_iam_member()),
        ]
    )


def _gcs_inventory(*, invoker_iam_disabled: bool = False) -> ResourceInventory:
    workload = _gcs_cloud_run()
    resources = [
        workload,
        _public_invoker(),
        _as_resource(_bucket()),
        _as_resource(_bucket_iam_member(role="roles/storage.objectUser")),
    ]
    if invoker_iam_disabled:
        workload.values["invoker_iam_disabled"] = True
    return GcpNormalizer().normalize(resources)


def _evidence(finding: Finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


class GcpCloudRunPublicInvocationRevalidationTests(unittest.TestCase):
    def test_removed_invoker_source_suppresses_all_firestore_findings(
        self,
    ) -> None:
        inventory = _firestore_inventory()
        self.assertEqual(
            {finding.rule_id for finding in _evaluate_inventory(inventory, _FIRESTORE_RULE_IDS)},
            _FIRESTORE_RULE_IDS,
        )

        current = _current_inventory(
            inventory,
            tuple(resource for resource in inventory.resources if resource.address != _PUBLIC_INVOKER_ADDRESS),
        )

        self.assertEqual(_evaluate_inventory(current, _FIRESTORE_RULE_IDS), [])

    def test_removed_invoker_source_suppresses_all_gcs_findings(self) -> None:
        inventory = _gcs_inventory()
        self.assertEqual(
            {finding.rule_id for finding in _evaluate_inventory(inventory, _GCS_RULE_IDS)},
            _GCS_RULE_IDS,
        )

        current = _current_inventory(
            inventory,
            tuple(resource for resource in inventory.resources if resource.address != _PUBLIC_INVOKER_ADDRESS),
        )

        self.assertEqual(_evaluate_inventory(current, _GCS_RULE_IDS), [])

    def test_changed_invoker_member_condition_or_target_fails_closed(
        self,
    ) -> None:
        cases = {
            "member": [
                {
                    "role": "roles/run.invoker",
                    "members": ["serviceAccount:private@example.iam.gserviceaccount.com"],
                }
            ],
            "condition": [
                {
                    "role": "roles/run.invoker",
                    "members": ["allUsers"],
                    "condition": {
                        "title": "runtime-window",
                        "expression": ('request.time < timestamp("2030-01-01T00:00:00Z")'),
                    },
                    "condition_state": "configured",
                }
            ],
        }
        for case, bindings in cases.items():
            with self.subTest(case=case):
                inventory = _firestore_inventory()
                source = inventory.get_by_address(_PUBLIC_INVOKER_ADDRESS)
                assert source is not None
                gcp_facts(source).set(
                    GcpResourceMetadata.IAM_BINDINGS,
                    bindings,
                )

                self.assertEqual(
                    _evaluate_inventory(inventory, _FIRESTORE_RULE_IDS),
                    [],
                )

        inventory = _firestore_inventory()
        source = inventory.get_by_address(_PUBLIC_INVOKER_ADDRESS)
        assert source is not None
        gcp_facts(source).set(
            GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE,
            "other-service",
        )
        self.assertEqual(
            _evaluate_inventory(inventory, _FIRESTORE_RULE_IDS),
            [],
        )

    def test_invoker_iam_check_disabled_is_current_gcs_public_posture(
        self,
    ) -> None:
        inventory = _gcs_inventory(invoker_iam_disabled=True)
        current = _current_inventory(
            inventory,
            tuple(resource for resource in inventory.resources if resource.address != _PUBLIC_INVOKER_ADDRESS),
        )
        findings = _evaluate_inventory(current, _GCS_RULE_IDS)

        self.assertEqual(
            {finding.rule_id for finding in findings},
            _GCS_RULE_IDS,
        )
        for finding in findings:
            self.assertNotIn(
                _PUBLIC_INVOKER_ADDRESS,
                finding.affected_resources,
            )
            evidence = _evidence(finding)
            self.assertNotIn("public_invoker_bindings", evidence)
            self.assertEqual(
                evidence["public_exposure_configuration"],
                ["invoker_iam_check=disabled; ingress=INGRESS_TRAFFIC_ALL"],
            )
            self.assertIn(
                "disables the Cloud Run Invoker IAM check",
                evidence["public_exposure_reasons"][0],
            )


if __name__ == "__main__":
    unittest.main()
