from __future__ import annotations

import unittest
from typing import Any

from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _EMAIL,
    _MEMBER,
    _PROJECT,
    _RING,
    _cloud_run,
    _custom_role,
    _key,
    _key_binding,
    _key_member,
    _project_member,
    _version,
    _workload,
)
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType


def _key_ring() -> TerraformResource:
    return _terraform_resource(
        "google_kms_key_ring.application",
        GcpResourceType.KMS_KEY_RING,
        {
            "id": _RING,
            "name": "application",
            "project": _PROJECT,
            "location": "global",
        },
    )


def _ring_member(
    name: str,
    *,
    condition: dict[str, str] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "key_ring_id": _RING,
        "role": "roles/cloudkms.admin",
        "member": _MEMBER,
    }
    if condition is not None:
        values["condition"] = [condition]
    return _terraform_resource(
        f"google_kms_key_ring_iam_member.{name}",
        GcpResourceType.KMS_KEY_RING_IAM_MEMBER,
        values,
    )


class GcpCloudRunKmsManagementPathTests(unittest.TestCase):
    def test_project_and_key_grants_project_exact_management_targets(self) -> None:
        version = _version(
            "data",
            "GOOGLE_SYMMETRIC_ENCRYPTION",
            state="ENABLED",
        )
        version.values["deletion_policy"] = "ABANDON"
        key = _key("data", "ENCRYPT_DECRYPT")
        key.values["rotation_period"] = "7776000s"
        key.values["destroy_scheduled_duration"] = "604800s"
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run(),
                _key_ring(),
                key,
                version,
                _project_member(
                    "runtime_project_admin",
                    "roles/cloudkms.admin",
                ),
                _key_member(
                    "runtime_key_admin",
                    "data",
                    "roles/cloudkms.admin",
                ),
            ]
        )

        facts = gcp_facts(_workload(inventory))
        paths = facts.cloud_run_kms_management_paths
        by_source: dict[str, list[dict[str, object]]] = {}
        for path in paths:
            by_source.setdefault(path["iam_resource_address"], []).append(path)

        project_paths = by_source["google_project_iam_member.runtime_project_admin"]
        self.assertEqual(
            {path["operation"] for path in project_paths},
            {
                "cloudkms.cryptoKeyVersions.update",
                "cloudkms.cryptoKeyVersions.destroy",
                "cloudkms.cryptoKeys.setIamPolicy",
                "cloudkms.keyRings.setIamPolicy",
            },
        )
        self.assertTrue(all(path["scope_type"] == "project" for path in project_paths))
        self.assertTrue(all(path["scope"] == _PROJECT for path in project_paths))

        key_paths = by_source["google_kms_crypto_key_iam_member.runtime_key_admin"]
        self.assertEqual(
            {path["operation"] for path in key_paths},
            {
                "cloudkms.cryptoKeyVersions.update",
                "cloudkms.cryptoKeyVersions.destroy",
                "cloudkms.cryptoKeys.setIamPolicy",
            },
        )
        self.assertFalse(any(path["operation"] == "cloudkms.keyRings.setIamPolicy" for path in key_paths))
        self.assertTrue(all(path["scope_type"] == "crypto_key" for path in key_paths))
        self.assertTrue(all(path["scope"] == f"{_RING}/cryptoKeys/data" for path in key_paths))

        version_paths = [path for path in paths if path["target_type"] == "crypto_key_version"]
        self.assertEqual(len(version_paths), 4)
        self.assertEqual(
            {path["operation"]: path["operation_class"] for path in version_paths if path["scope_type"] == "project"},
            {
                "cloudkms.cryptoKeyVersions.update": ("disruptive_administration"),
                "cloudkms.cryptoKeyVersions.destroy": ("destructive_administration"),
            },
        )
        self.assertTrue(all(path["target_address"] == "google_kms_crypto_key_version.data" for path in version_paths))
        self.assertTrue(
            all(
                path["target_resource_name"] == f"{_RING}/cryptoKeys/data/cryptoKeyVersions/1" for path in version_paths
            )
        )
        self.assertTrue(all(path["iam_scope_is_key_version"] is False for path in version_paths))
        destroy = next(
            path
            for path in version_paths
            if path["operation"] == "cloudkms.cryptoKeyVersions.destroy" and path["scope_type"] == "project"
        )
        assert destroy["key_version"] is not None
        self.assertEqual(destroy["key_version"]["state"], "ENABLED")
        self.assertEqual(
            destroy["lifecycle_compatibility_state"],
            "compatible",
        )
        self.assertEqual(
            destroy["key_version"]["destroy_scheduled_duration"],
            "604800s",
        )
        self.assertEqual(
            destroy["key_version"]["deletion_policy_state"],
            "abandon",
        )

        ring_path = next(path for path in paths if path["operation"] == "cloudkms.keyRings.setIamPolicy")
        self.assertEqual(ring_path["management_effect"], "delegation")
        self.assertEqual(ring_path["target_type"], "key_ring")
        self.assertEqual(
            ring_path["target_address"],
            "google_kms_key_ring.application",
        )
        self.assertEqual(ring_path["target_resource_name"], _RING)
        self.assertEqual(
            ring_path["target_model_evidence_addresses"],
            [
                "google_kms_crypto_key.data",
                "google_kms_key_ring.application",
            ],
        )
        self.assertFalse(any(path["target_type"] == "project" for path in paths))
        self.assertEqual(facts.cloud_run_kms_operation_paths, [])

    def test_standalone_key_ring_receives_project_management_path(
        self,
    ) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run(),
                _key_ring(),
                _project_member(
                    "runtime_project_admin",
                    "roles/cloudkms.admin",
                ),
            ]
        )

        workload = _workload(inventory)
        ring = inventory.get_by_address("google_kms_key_ring.application")
        assert ring is not None
        ring_grants = gcp_facts(ring).kms_key_ring_iam_grants
        self.assertEqual(len(ring_grants), 1)
        self.assertEqual(ring_grants[0]["scope_type"], "project")
        self.assertIn(
            "cloudkms.keyRings.setIamPolicy",
            ring_grants[0]["scope_effective_permissions"],
        )

        paths = gcp_facts(workload).cloud_run_kms_management_paths
        self.assertEqual(len(paths), 1)
        path = paths[0]
        self.assertEqual(
            path["operation"],
            "cloudkms.keyRings.setIamPolicy",
        )
        self.assertEqual(path["target_type"], "key_ring")
        self.assertEqual(path["target_address"], ring.address)
        self.assertEqual(path["target_resource_name"], _RING)
        self.assertEqual(
            path["target_model_evidence_addresses"],
            [ring.address],
        )
        self.assertEqual(path["scope_type"], "project")

    def test_standalone_key_ring_condition_remains_uncertain(
        self,
    ) -> None:
        condition = {
            "title": "maintenance-window",
            "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
        }
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run(),
                _key_ring(),
                _ring_member(
                    "conditioned_admin",
                    condition=condition,
                ),
            ]
        )

        facts = gcp_facts(_workload(inventory))
        self.assertEqual(facts.cloud_run_kms_management_paths, [])
        self.assertTrue(
            any(
                "authorization_state=conditional" in uncertainty
                for uncertainty in (facts.cloud_run_kms_management_path_uncertainties)
            )
        )

    def test_unresolved_standalone_key_ring_remains_uncertain(
        self,
    ) -> None:
        unresolved_ring = _terraform_resource(
            "google_kms_key_ring.unresolved",
            GcpResourceType.KMS_KEY_RING,
            {
                "name": "unresolved",
                "project": None,
                "location": None,
                "id": None,
            },
            unknown_values={
                "project": True,
                "location": True,
                "id": True,
            },
        )
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run(),
                unresolved_ring,
                _project_member(
                    "runtime_project_admin",
                    "roles/cloudkms.admin",
                ),
            ]
        )

        facts = gcp_facts(_workload(inventory))
        self.assertEqual(facts.cloud_run_kms_management_paths, [])
        self.assertTrue(
            any(
                "exact Cloud KMS key-ring ancestry is unresolved" in uncertainty
                for uncertainty in (facts.cloud_run_kms_management_path_uncertainties)
            )
        )

    def test_project_ring_policy_fanout_deduplicates_ring_target(
        self,
    ) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run(),
                _key_ring(),
                _key("data", "ENCRYPT_DECRYPT"),
                _key("signing", "ASYMMETRIC_SIGN"),
                _project_member(
                    "runtime_project_admin",
                    "roles/cloudkms.admin",
                ),
            ]
        )

        paths = gcp_facts(_workload(inventory)).cloud_run_kms_management_paths
        ring_paths = [path for path in paths if path["operation"] == "cloudkms.keyRings.setIamPolicy"]
        self.assertEqual(len(ring_paths), 1)
        self.assertEqual(
            ring_paths[0]["target_model_evidence_addresses"],
            [
                "google_kms_crypto_key.data",
                "google_kms_crypto_key.signing",
                "google_kms_key_ring.application",
            ],
        )
        self.assertEqual(
            len([path for path in paths if path["operation"] == "cloudkms.cryptoKeys.setIamPolicy"]),
            2,
        )

    def test_custom_role_projects_only_cataloged_management_permissions(
        self,
    ) -> None:
        role_name = f"projects/{_PROJECT}/roles/runtimeCrypto"
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run(),
                _key("data", "ENCRYPT_DECRYPT"),
                _version("data", "GOOGLE_SYMMETRIC_ENCRYPTION"),
                _custom_role(
                    "runtime",
                    [
                        "cloudkms.cryptoKeyVersions.update",
                        "cloudkms.cryptoKeys.setIamPolicy",
                        "cloudkms.cryptoKeys.delete",
                        "resourcemanager.projects.setIamPolicy",
                    ],
                ),
                _key_member("runtime_custom", "data", role_name),
            ]
        )

        paths = gcp_facts(_workload(inventory)).cloud_run_kms_management_paths
        self.assertEqual(
            {path["operation"] for path in paths},
            {
                "cloudkms.cryptoKeyVersions.update",
                "cloudkms.cryptoKeys.setIamPolicy",
            },
        )
        self.assertTrue(all(path["role_kind"] == "custom" for path in paths))
        self.assertTrue(
            all(path["role_definition_address"] == "google_project_iam_custom_role.runtime" for path in paths)
        )
        self.assertFalse(
            any(
                permission == "resourcemanager.projects.setIamPolicy"
                for path in paths
                for permission in path["matched_permissions"]
            )
        )

    def test_conditioned_and_ambiguous_admin_grants_remain_uncertain(
        self,
    ) -> None:
        condition = {
            "title": "maintenance-window",
            "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
        }
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run(),
                _key("conditional", "ENCRYPT_DECRYPT"),
                _version("conditional", "GOOGLE_SYMMETRIC_ENCRYPTION"),
                _key("ambiguous", "ENCRYPT_DECRYPT"),
                _version("ambiguous", "GOOGLE_SYMMETRIC_ENCRYPTION"),
                _ring_member(
                    "conditioned_admin",
                    condition=condition,
                ),
                _key_binding(
                    "ambiguous_admins",
                    "ambiguous",
                    "roles/cloudkms.admin",
                ),
                _key_member(
                    "ambiguous_admin",
                    "ambiguous",
                    "roles/cloudkms.admin",
                ),
            ]
        )

        facts = gcp_facts(_workload(inventory))
        self.assertEqual(facts.cloud_run_kms_management_paths, [])
        self.assertTrue(
            any(
                "authorization_state=conditional" in uncertainty
                for uncertainty in facts.cloud_run_kms_management_path_uncertainties
            )
        )
        self.assertTrue(
            any(
                "management_state=ambiguous" in uncertainty
                for uncertainty in facts.cloud_run_kms_management_path_uncertainties
            )
        )

    def test_incompatible_version_lifecycle_stays_quiet(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run(),
                _key("data", "ENCRYPT_DECRYPT"),
                _version(
                    "data",
                    "GOOGLE_SYMMETRIC_ENCRYPTION",
                    state="DESTROY_SCHEDULED",
                ),
                _project_member(
                    "runtime_project_admin",
                    "roles/cloudkms.admin",
                ),
            ]
        )

        facts = gcp_facts(_workload(inventory))
        self.assertEqual(
            {path["operation"] for path in facts.cloud_run_kms_management_paths},
            {
                "cloudkms.cryptoKeys.setIamPolicy",
                "cloudkms.keyRings.setIamPolicy",
            },
        )
        self.assertFalse(
            any(path["target_type"] == "crypto_key_version" for path in facts.cloud_run_kms_management_paths)
        )
        self.assertEqual(
            facts.cloud_run_kms_management_path_uncertainties,
            [],
        )

    def test_unresolved_version_identity_is_not_promoted_to_key_target(
        self,
    ) -> None:
        version = _version("data", "GOOGLE_SYMMETRIC_ENCRYPTION")
        version.values["id"] = None
        version.values["name"] = None
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run(),
                _key("data", "ENCRYPT_DECRYPT"),
                version,
                _project_member(
                    "runtime_project_admin",
                    "roles/cloudkms.admin",
                ),
            ]
        )

        facts = gcp_facts(_workload(inventory))
        self.assertEqual(
            {path["operation"] for path in facts.cloud_run_kms_management_paths},
            {
                "cloudkms.cryptoKeys.setIamPolicy",
                "cloudkms.keyRings.setIamPolicy",
            },
        )
        self.assertTrue(
            any(
                "unresolved exact identity" in uncertainty
                for uncertainty in facts.cloud_run_kms_management_path_uncertainties
            )
        )

    def test_unresolved_version_crypto_key_ancestry_remains_uncertain(
        self,
    ) -> None:
        version = _version("data", "GOOGLE_SYMMETRIC_ENCRYPTION")
        for field in ("crypto_key", "id", "name"):
            version.values[field] = None
            version.unknown_values[field] = True
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run(),
                _key("data", "ENCRYPT_DECRYPT"),
                version,
                _project_member(
                    "runtime_project_admin",
                    "roles/cloudkms.admin",
                ),
            ]
        )

        facts = gcp_facts(_workload(inventory))
        self.assertFalse(
            any(path["target_type"] == "crypto_key_version" for path in facts.cloud_run_kms_management_paths)
        )
        self.assertTrue(
            any(
                "unresolved exact CryptoKey ancestry" in uncertainty
                for uncertainty in facts.cloud_run_kms_management_path_uncertainties
            )
        )

    def test_malformed_key_ring_path_remains_uncertain(self) -> None:
        malformed_ring = _terraform_resource(
            "google_kms_key_ring.malformed",
            GcpResourceType.KMS_KEY_RING,
            {
                "id": f"{_RING}/extra",
                "name": "application",
                "project": _PROJECT,
                "location": "global",
            },
        )
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run(),
                malformed_ring,
                _project_member(
                    "runtime_project_admin",
                    "roles/cloudkms.admin",
                ),
            ]
        )

        facts = gcp_facts(_workload(inventory))
        self.assertEqual(facts.cloud_run_kms_management_paths, [])
        self.assertTrue(
            any(
                "exact Cloud KMS key-ring ancestry is unresolved" in uncertainty
                for uncertainty in facts.cloud_run_kms_management_path_uncertainties
            )
        )

    def test_unresolved_version_ancestry_without_runtime_management_authority_stays_quiet(
        self,
    ) -> None:
        version = _version("data", "GOOGLE_SYMMETRIC_ENCRYPTION")
        for field in ("crypto_key", "id", "name"):
            version.values[field] = None
            version.unknown_values[field] = True
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run(),
                _key("data", "ENCRYPT_DECRYPT"),
                version,
            ]
        )

        facts = gcp_facts(_workload(inventory))
        self.assertEqual(facts.cloud_run_kms_management_paths, [])
        self.assertEqual(facts.cloud_run_kms_management_path_uncertainties, [])

    def test_unresolved_version_ancestry_for_other_admin_member_stays_quiet(
        self,
    ) -> None:
        version = _version("data", "GOOGLE_SYMMETRIC_ENCRYPTION")
        for field in ("crypto_key", "id", "name"):
            version.values[field] = None
            version.unknown_values[field] = True
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run(),
                _key("data", "ENCRYPT_DECRYPT"),
                version,
                _project_member(
                    "other_admin",
                    "roles/cloudkms.admin",
                    member="serviceAccount:other@tfstride-demo.iam.gserviceaccount.com",
                ),
            ]
        )

        facts = gcp_facts(_workload(inventory))
        self.assertEqual(facts.cloud_run_kms_management_paths, [])
        self.assertEqual(facts.cloud_run_kms_management_path_uncertainties, [])

    def test_unknown_version_lifecycle_remains_uncertain(self) -> None:
        version = _version("data", "GOOGLE_SYMMETRIC_ENCRYPTION")
        version.values["state"] = None
        version.unknown_values["state"] = True
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run(),
                _key("data", "ENCRYPT_DECRYPT"),
                version,
                _project_member(
                    "runtime_project_admin",
                    "roles/cloudkms.admin",
                ),
            ]
        )

        facts = gcp_facts(_workload(inventory))
        self.assertFalse(
            any(path["target_type"] == "crypto_key_version" for path in facts.cloud_run_kms_management_paths)
        )
        self.assertTrue(
            any(
                "lifecycle state is unresolved" in uncertainty
                for uncertainty in (facts.cloud_run_kms_management_path_uncertainties)
            )
        )

    def test_other_runtime_member_admin_stays_quiet(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run(service_account=_EMAIL),
                _key("data", "ENCRYPT_DECRYPT"),
                _version("data", "GOOGLE_SYMMETRIC_ENCRYPTION"),
                _project_member(
                    "other_admin",
                    "roles/cloudkms.admin",
                    member=("serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"),
                ),
            ]
        )

        facts = gcp_facts(_workload(inventory))
        self.assertEqual(facts.cloud_run_kms_management_paths, [])
        self.assertEqual(
            facts.cloud_run_kms_management_path_uncertainties,
            [],
        )


if __name__ == "__main__":
    unittest.main()
