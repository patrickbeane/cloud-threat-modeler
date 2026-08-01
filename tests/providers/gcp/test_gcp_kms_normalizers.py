from __future__ import annotations

from tests.providers.gcp.normalizer_support import (
    GcpNormalizerTestCase,
    _terraform_resource,
)
from tfstride.models import ResourceCategory
from tfstride.providers.gcp.kms_normalizers import normalize_kms_crypto_key
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts import gcp_facts


class GcpKmsNormalizerTests(GcpNormalizerTestCase):
    def test_kms_crypto_key_normalizer_preserves_key_context(self) -> None:
        normalized = normalize_kms_crypto_key(self.resources["google_kms_crypto_key.customer"])

        self.assertEqual(normalized.category, ResourceCategory.DATA)
        self.assertEqual(
            normalized.identifier,
            "projects/tfstride-demo/locations/global/keyRings/tfstride-app/cryptoKeys/tfstride-customer-key",
        )
        self.assertEqual(normalized.data_sensitivity, "sensitive")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.PROJECT), "tfstride-demo")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.KMS_PURPOSE), "ENCRYPT_DECRYPT")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.KMS_ROTATION_PERIOD), "7776000s")
        facts = gcp_facts(normalized)
        self.assertEqual(facts.kms_purpose, "ENCRYPT_DECRYPT")
        self.assertEqual(facts.kms_rotation_period, "7776000s")
        self.assertIsNone(facts.kms_destroy_scheduled_duration)
        self.assertEqual(facts.kms_posture_uncertainties, [])
        self.assertTrue(normalized.storage_encrypted)

    def test_kms_crypto_key_normalizer_preserves_destroy_scheduled_duration(self) -> None:
        normalized = normalize_kms_crypto_key(
            _terraform_resource(
                "google_kms_crypto_key.customer",
                "google_kms_crypto_key",
                {
                    "name": "tfstride-customer-key",
                    "key_ring": "projects/tfstride-demo/locations/global/keyRings/tfstride-app",
                    "purpose": "ENCRYPT_DECRYPT",
                    "destroy_scheduled_duration": "604800s",
                },
            )
        )

        facts = gcp_facts(normalized)
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.KMS_DESTROY_SCHEDULED_DURATION),
            "604800s",
        )
        self.assertEqual(facts.kms_destroy_scheduled_duration, "604800s")
        self.assertEqual(facts.kms_posture_uncertainties, [])

    def test_kms_crypto_key_normalizer_preserves_unknown_rotation_period(self) -> None:
        normalized = normalize_kms_crypto_key(
            _terraform_resource(
                "google_kms_crypto_key.customer",
                "google_kms_crypto_key",
                {
                    "name": "tfstride-customer-key",
                    "key_ring": "projects/tfstride-demo/locations/global/keyRings/tfstride-app",
                    "purpose": "ENCRYPT_DECRYPT",
                },
                unknown_values={"rotation_period": True},
            )
        )

        facts = gcp_facts(normalized)
        self.assertIsNone(facts.kms_rotation_period)
        self.assertEqual(facts.kms_posture_uncertainties, ["rotation_period is unknown after planning"])

    def test_kms_crypto_key_normalizer_preserves_unknown_destroy_scheduled_duration(self) -> None:
        normalized = normalize_kms_crypto_key(
            _terraform_resource(
                "google_kms_crypto_key.customer",
                "google_kms_crypto_key",
                {
                    "name": "tfstride-customer-key",
                    "key_ring": "projects/tfstride-demo/locations/global/keyRings/tfstride-app",
                    "purpose": "ENCRYPT_DECRYPT",
                    "destroy_scheduled_duration": "86400s",
                },
                unknown_values={"destroy_scheduled_duration": True},
            )
        )

        facts = gcp_facts(normalized)
        self.assertIsNone(facts.kms_destroy_scheduled_duration)
        self.assertEqual(
            facts.kms_posture_uncertainties,
            ["destroy_scheduled_duration is unknown after planning"],
        )
