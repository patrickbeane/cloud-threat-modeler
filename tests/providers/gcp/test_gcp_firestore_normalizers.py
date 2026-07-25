from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.models import ResourceCategory
from tfstride.providers.gcp.firestore_normalizers import normalize_firestore_database
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType


class GcpFirestoreNormalizerTests(unittest.TestCase):
    def test_firestore_database_preserves_protection_and_deletion_posture(self) -> None:
        normalized = normalize_firestore_database(
            _terraform_resource(
                "google_firestore_database.orders",
                GcpResourceType.FIRESTORE_DATABASE,
                {
                    "id": "projects/tfstride-demo/databases/orders",
                    "name": "orders",
                    "project": "tfstride-demo",
                    "location_id": "nam5",
                    "type": "FIRESTORE_NATIVE",
                    "cmek_config": [
                        {"kms_key_name": ("projects/tfstride-demo/locations/us/keyRings/data/cryptoKeys/firestore")}
                    ],
                    "point_in_time_recovery_enablement": "POINT_IN_TIME_RECOVERY_ENABLED",
                    "delete_protection_state": "DELETE_PROTECTION_ENABLED",
                    "deletion_policy": "ABANDON",
                },
            )
        )

        facts = gcp_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.DATA)
        self.assertEqual(normalized.identifier, "projects/tfstride-demo/databases/orders")
        self.assertTrue(normalized.storage_encrypted)
        self.assertEqual(facts.firestore_database_type, "FIRESTORE_NATIVE")
        self.assertEqual(facts.firestore_location, "nam5")
        self.assertEqual(
            facts.firestore_cmek_key_name,
            "projects/tfstride-demo/locations/us/keyRings/data/cryptoKeys/firestore",
        )
        self.assertEqual(facts.firestore_cmek_state, "configured")
        self.assertTrue(facts.firestore_customer_managed_encryption)
        self.assertEqual(facts.firestore_pitr_enablement, "POINT_IN_TIME_RECOVERY_ENABLED")
        self.assertEqual(facts.firestore_pitr_state, "enabled")
        self.assertTrue(facts.firestore_pitr_enabled)
        self.assertEqual(facts.firestore_delete_protection_state, "DELETE_PROTECTION_ENABLED")
        self.assertEqual(facts.firestore_delete_protection_enablement, "enabled")
        self.assertTrue(facts.firestore_delete_protection_enabled)
        self.assertEqual(facts.firestore_terraform_deletion_policy, "ABANDON")
        self.assertEqual(facts.firestore_terraform_deletion_policy_state, "configured")
        self.assertEqual(facts.firestore_posture_uncertainties, [])
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.FIRESTORE_CMEK_CONFIG),
            {"kms_key_name": "projects/tfstride-demo/locations/us/keyRings/data/cryptoKeys/firestore"},
        )

    def test_firestore_database_distinguishes_explicit_disablement_from_terraform_policy(self) -> None:
        normalized = normalize_firestore_database(
            _terraform_resource(
                "google_firestore_database.default",
                GcpResourceType.FIRESTORE_DATABASE,
                {
                    "name": "(default)",
                    "location_id": "nam5",
                    "type": "FIRESTORE_NATIVE",
                    "point_in_time_recovery_enablement": "POINT_IN_TIME_RECOVERY_DISABLED",
                    "delete_protection_state": "DELETE_PROTECTION_DISABLED",
                    "deletion_policy": "DELETE",
                },
            )
        )

        facts = gcp_facts(normalized)

        self.assertEqual(facts.firestore_cmek_state, "not_configured")
        self.assertFalse(facts.firestore_customer_managed_encryption)
        self.assertEqual(facts.firestore_pitr_state, "disabled")
        self.assertFalse(facts.firestore_pitr_enabled)
        self.assertEqual(facts.firestore_delete_protection_enablement, "disabled")
        self.assertFalse(facts.firestore_delete_protection_enabled)
        self.assertEqual(facts.firestore_terraform_deletion_policy, "DELETE")
        self.assertEqual(facts.firestore_terraform_deletion_policy_state, "configured")
        self.assertNotEqual(
            facts.firestore_delete_protection_enablement,
            facts.firestore_terraform_deletion_policy_state,
        )
        self.assertEqual(facts.firestore_posture_uncertainties, [])

    def test_firestore_database_missing_optional_posture_is_not_configured(self) -> None:
        normalized = normalize_firestore_database(
            _terraform_resource(
                "google_firestore_database.minimal",
                GcpResourceType.FIRESTORE_DATABASE,
                {
                    "name": "minimal",
                    "location_id": "nam5",
                    "type": "DATASTORE_MODE",
                },
            )
        )

        facts = gcp_facts(normalized)

        self.assertEqual(facts.firestore_cmek_state, "not_configured")
        self.assertIsNone(facts.firestore_cmek_key_name)
        self.assertEqual(facts.firestore_pitr_state, "not_configured")
        self.assertEqual(facts.firestore_delete_protection_enablement, "not_configured")
        self.assertEqual(facts.firestore_terraform_deletion_policy_state, "not_configured")
        self.assertEqual(facts.firestore_posture_uncertainties, [])

    def test_firestore_database_preserves_unknown_posture_values(self) -> None:
        normalized = normalize_firestore_database(
            _terraform_resource(
                "google_firestore_database.unknown",
                GcpResourceType.FIRESTORE_DATABASE,
                {"name": "unknown", "type": "FIRESTORE_NATIVE"},
                unknown_values={
                    "location_id": True,
                    "cmek_config": True,
                    "point_in_time_recovery_enablement": True,
                    "delete_protection_state": True,
                    "deletion_policy": True,
                },
            )
        )

        facts = gcp_facts(normalized)

        self.assertIsNone(facts.firestore_location)
        self.assertEqual(facts.firestore_cmek_state, "unknown")
        self.assertEqual(facts.firestore_pitr_state, "unknown")
        self.assertEqual(facts.firestore_delete_protection_enablement, "unknown")
        self.assertEqual(facts.firestore_terraform_deletion_policy_state, "unknown")
        self.assertEqual(
            facts.firestore_posture_uncertainties,
            [
                "location_id is unknown after planning",
                "cmek_config is unknown after planning",
                "point_in_time_recovery_enablement is unknown after planning",
                "delete_protection_state is unknown after planning",
                "deletion_policy is unknown after planning",
            ],
        )


if __name__ == "__main__":
    unittest.main()
