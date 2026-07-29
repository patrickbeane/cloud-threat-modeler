from __future__ import annotations

import unittest
from typing import Any

from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts

_KEY_RING = "projects/tfstride-demo/locations/global/keyRings/application"
_KEY_PATH = f"{_KEY_RING}/cryptoKeys/customer"
_VERSION_PATH = f"{_KEY_PATH}/cryptoKeyVersions/1"


def _resource(
    resource_type: str,
    name: str,
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/google",
        values=values,
        unknown_values=unknown_values or {},
    )


def _key(
    *,
    unknown_values: dict[str, Any] | None = None,
    **values: Any,
) -> TerraformResource:
    defaults: dict[str, Any] = {
        "id": _KEY_PATH,
        "name": "customer",
        "key_ring": _KEY_RING,
        "purpose": "ENCRYPT_DECRYPT",
        "rotation_period": "7776000s",
        "destroy_scheduled_duration": "604800s",
    }
    defaults.update(values)
    return _resource(
        "google_kms_crypto_key",
        "customer",
        defaults,
        unknown_values=unknown_values,
    )


def _version(
    values: dict[str, Any] | None = None,
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    version_values: dict[str, Any] = {
        "crypto_key": "google_kms_crypto_key.customer.id",
        "id": _VERSION_PATH,
        "name": _VERSION_PATH,
        "state": "ENABLED",
        "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
        "protection_level": "SOFTWARE",
        "generate_time": "2026-07-19T00:00:00Z",
    }
    version_values.update(values or {})
    return _resource(
        "google_kms_crypto_key_version",
        "primary",
        version_values,
        unknown_values=unknown_values,
    )


class GcpKmsCryptoKeyVersionNormalizerTests(unittest.TestCase):
    def test_version_preserves_exact_ancestry_and_inherits_key_posture(self) -> None:
        inventory = GcpNormalizer().normalize([_key(), _version()])
        version = inventory.get_by_address("google_kms_crypto_key_version.primary")
        assert version is not None

        facts = gcp_facts(version)
        self.assertEqual(version.identifier, _VERSION_PATH)
        self.assertEqual(facts.kms_crypto_key_version_reference, _VERSION_PATH)
        self.assertEqual(facts.kms_crypto_key_version_name, _VERSION_PATH)
        self.assertEqual(facts.kms_crypto_key_version_number, "1")
        self.assertEqual(facts.kms_crypto_key_version_crypto_key_reference, "google_kms_crypto_key.customer.id")
        self.assertEqual(facts.kms_crypto_key_version_crypto_key_path, _KEY_PATH)
        self.assertEqual(facts.project, "tfstride-demo")
        self.assertEqual(facts.kms_crypto_key_version_key_ring, _KEY_RING)
        self.assertEqual(
            facts.kms_crypto_key_version_resolved_key_address,
            "google_kms_crypto_key.customer",
        )
        self.assertEqual(facts.kms_crypto_key_version_purpose, "ENCRYPT_DECRYPT")
        self.assertEqual(facts.kms_crypto_key_version_algorithm, "GOOGLE_SYMMETRIC_ENCRYPTION")
        self.assertEqual(facts.kms_crypto_key_version_protection_level, "SOFTWARE")
        self.assertEqual(facts.kms_crypto_key_version_state, "ENABLED")
        self.assertEqual(facts.kms_crypto_key_version_generate_time, "2026-07-19T00:00:00Z")
        self.assertEqual(facts.kms_crypto_key_version_rotation_period, "7776000s")
        self.assertEqual(facts.kms_crypto_key_version_destroy_scheduled_duration, "604800s")
        self.assertEqual(facts.kms_crypto_key_version_import_posture, "generated")
        self.assertEqual(facts.kms_crypto_key_version_deletion_policy, "DELETE")
        self.assertEqual(facts.kms_crypto_key_version_deletion_policy_state, "delete")
        self.assertEqual(facts.kms_crypto_key_version_posture_uncertainties, [])

    def test_unknown_parent_purpose_is_not_defaulted(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _key(unknown_values={"purpose": True}),
                _version(),
            ]
        )
        version = inventory.get_by_address("google_kms_crypto_key_version.primary")
        assert version is not None

        facts = gcp_facts(version)
        self.assertIsNone(facts.kms_crypto_key_version_purpose)
        self.assertTrue(
            any(
                "parent crypto key google_kms_crypto_key.customer: purpose is unknown after planning" in item
                for item in facts.kms_crypto_key_version_posture_uncertainties
            )
        )

    def test_sparse_version_resolves_full_crypto_key_path_without_computed_id(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _key(),
                _version(
                    {
                        "id": None,
                        "name": _VERSION_PATH,
                        "crypto_key": _KEY_PATH,
                    }
                ),
            ]
        )
        version = inventory.get_by_address("google_kms_crypto_key_version.primary")
        assert version is not None

        facts = gcp_facts(version)
        self.assertEqual(facts.kms_crypto_key_version_crypto_key_path, _KEY_PATH)
        self.assertEqual(
            facts.kms_crypto_key_version_resolved_key_address,
            "google_kms_crypto_key.customer",
        )

    def test_parent_resolution_does_not_depend_on_plan_resource_order(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _version({"crypto_key": _KEY_PATH}),
                _key(),
            ]
        )
        version = inventory.get_by_address("google_kms_crypto_key_version.primary")
        assert version is not None

        self.assertEqual(
            gcp_facts(version).kms_crypto_key_version_resolved_key_address,
            "google_kms_crypto_key.customer",
        )

    def test_external_version_preserves_external_key_uri(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _key(),
                _version(
                    {
                        "state": "ENABLED",
                        "protection_level": "EXTERNAL",
                        "generate_time": None,
                        "external_protection_level_options": [{"external_key_uri": "https://ekm.example/keys/orders"}],
                    }
                ),
            ]
        )
        version = inventory.get_by_address("google_kms_crypto_key_version.primary")
        assert version is not None

        facts = gcp_facts(version)
        self.assertEqual(facts.kms_crypto_key_version_import_posture, "external_protection")
        self.assertEqual(
            facts.kms_crypto_key_version_external_key_uri,
            "https://ekm.example/keys/orders",
        )
        self.assertIsNone(facts.kms_crypto_key_version_ekm_connection_key_path)

    def test_external_vpc_version_preserves_ekm_connection_key_path(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _key(),
                _version(
                    {
                        "state": "ENABLED",
                        "protection_level": "EXTERNAL_VPC",
                        "generate_time": None,
                        "external_protection_level_options": [
                            {
                                "ekm_connection_key_path": (
                                    "v0/projects/tfstride-demo/locations/global/"
                                    "ekmConnections/orders/cryptoKeys/customer"
                                )
                            }
                        ],
                    }
                ),
            ]
        )
        version = inventory.get_by_address("google_kms_crypto_key_version.primary")
        assert version is not None

        facts = gcp_facts(version)
        self.assertEqual(facts.kms_crypto_key_version_import_posture, "external_protection")
        self.assertIsNone(facts.kms_crypto_key_version_external_key_uri)
        self.assertEqual(
            facts.kms_crypto_key_version_ekm_connection_key_path,
            ("v0/projects/tfstride-demo/locations/global/ekmConnections/orders/cryptoKeys/customer"),
        )

    def test_unknown_external_option_field_does_not_preserve_stale_value(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _key(),
                _version(
                    {
                        "protection_level": "EXTERNAL",
                        "generate_time": None,
                        "external_protection_level_options": [{"external_key_uri": "https://old.example/keys/orders"}],
                    },
                    unknown_values={"external_protection_level_options": [{"external_key_uri": True}]},
                ),
            ]
        )
        version = inventory.get_by_address("google_kms_crypto_key_version.primary")
        assert version is not None

        facts = gcp_facts(version)
        self.assertEqual(facts.kms_crypto_key_version_import_posture, "unknown")
        self.assertIsNone(facts.kms_crypto_key_version_external_key_uri)
        self.assertNotIn(
            "external_key_uri",
            facts.kms_crypto_key_version_external_protection_level_options,
        )
        self.assertTrue(
            any(
                "external_protection_level_options.external_key_uri is unknown after planning" in item
                for item in facts.kms_crypto_key_version_posture_uncertainties
            )
        )

    def test_pending_import_and_deletion_posture_are_preserved(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _key(),
                _version(
                    {
                        "state": "PENDING_IMPORT",
                        "generate_time": None,
                        "deletion_policy": "PREVENT",
                    }
                ),
            ]
        )
        version = inventory.get_by_address("google_kms_crypto_key_version.primary")
        assert version is not None

        facts = gcp_facts(version)
        self.assertEqual(facts.kms_crypto_key_version_state, "PENDING_IMPORT")
        self.assertEqual(facts.kms_crypto_key_version_import_posture, "import_pending")
        self.assertEqual(facts.kms_crypto_key_version_deletion_policy, "PREVENT")
        self.assertEqual(facts.kms_crypto_key_version_deletion_policy_state, "prevent")

    def test_unknown_version_posture_remains_uncertain(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _key(),
                _version(
                    unknown_values={
                        "state": True,
                        "algorithm": True,
                        "protection_level": True,
                        "generate_time": True,
                        "external_protection_level_options": True,
                        "deletion_policy": True,
                    }
                ),
            ]
        )
        version = inventory.get_by_address("google_kms_crypto_key_version.primary")
        assert version is not None

        facts = gcp_facts(version)
        self.assertEqual(facts.kms_crypto_key_version_import_posture, "unknown")
        self.assertEqual(facts.kms_crypto_key_version_deletion_policy, None)
        self.assertEqual(facts.kms_crypto_key_version_deletion_policy_state, "unknown")
        self.assertTrue(facts.kms_crypto_key_version_posture_uncertainties)
        self.assertTrue(
            any(
                "state is unknown after planning" in item for item in facts.kms_crypto_key_version_posture_uncertainties
            )
        )

    def test_version_name_resolves_parent_when_crypto_key_is_unknown(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _key(),
                _version(
                    {"crypto_key": None},
                    unknown_values={"crypto_key": True},
                ),
            ]
        )
        version = inventory.get_by_address("google_kms_crypto_key_version.primary")
        assert version is not None

        facts = gcp_facts(version)
        self.assertEqual(
            facts.kms_crypto_key_version_resolved_key_address,
            "google_kms_crypto_key.customer",
        )
        self.assertTrue(
            any(
                "crypto_key is unknown after planning" in item
                for item in facts.kms_crypto_key_version_posture_uncertainties
            )
        )
        self.assertFalse(any("is unresolved" in item for item in facts.kms_crypto_key_version_posture_uncertainties))

    def test_unknown_protection_level_does_not_become_not_configured(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _key(),
                _version(
                    unknown_values={"protection_level": True},
                ),
            ]
        )
        version = inventory.get_by_address("google_kms_crypto_key_version.primary")
        assert version is not None

        facts = gcp_facts(version)
        self.assertEqual(facts.kms_crypto_key_version_state, "ENABLED")
        self.assertEqual(facts.kms_crypto_key_version_import_posture, "unknown")
        self.assertTrue(
            any(
                "protection_level is unknown after planning" in item
                for item in facts.kms_crypto_key_version_posture_uncertainties
            )
        )

    def test_enabled_version_without_generation_evidence_is_unknown(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _key(),
                _version({"generate_time": None}),
            ]
        )
        version = inventory.get_by_address("google_kms_crypto_key_version.primary")
        assert version is not None

        self.assertEqual(
            gcp_facts(version).kms_crypto_key_version_import_posture,
            "unknown",
        )

    def test_unresolved_crypto_key_reference_does_not_invent_parent_posture(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _version({"crypto_key": "google_kms_crypto_key.external.id"}),
            ]
        )
        version = inventory.get_by_address("google_kms_crypto_key_version.primary")
        assert version is not None

        facts = gcp_facts(version)
        self.assertIsNone(facts.kms_crypto_key_version_resolved_key_address)
        self.assertIsNone(facts.kms_crypto_key_version_purpose)
        self.assertTrue(
            any(
                "google_kms_crypto_key.external.id" in item and "is unresolved" in item
                for item in facts.kms_crypto_key_version_posture_uncertainties
            )
        )

    def test_version_does_not_become_a_key_iam_grant_target(self) -> None:
        inventory = GcpNormalizer().normalize([_key(), _version()])
        version = inventory.get_by_address("google_kms_crypto_key_version.primary")
        assert version is not None
        self.assertEqual(gcp_facts(version).bindings, [])
        self.assertEqual(gcp_facts(version).resource_policy_source_addresses, [])


if __name__ == "__main__":
    unittest.main()
