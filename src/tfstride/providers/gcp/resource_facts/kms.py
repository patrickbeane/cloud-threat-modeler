from __future__ import annotations

from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts.base import GcpBaseFacts


class GcpKmsFacts(GcpBaseFacts):
    __slots__ = ()

    @property
    def kms_crypto_key_reference(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE)

    @property
    def kms_key_ring(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_KEY_RING)

    @property
    def kms_purpose(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_PURPOSE)

    @property
    def kms_rotation_period(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_ROTATION_PERIOD)

    @property
    def kms_destroy_scheduled_duration(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_DESTROY_SCHEDULED_DURATION)

    @property
    def kms_posture_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.KMS_POSTURE_UNCERTAINTIES)

    @property
    def kms_crypto_key_version_reference(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_REFERENCE)

    @property
    def kms_crypto_key_version_name(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_NAME)

    @property
    def kms_crypto_key_version_number(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_NUMBER)

    @property
    def kms_crypto_key_version_crypto_key_reference(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_CRYPTO_KEY_REFERENCE)

    @property
    def kms_crypto_key_version_key_ring(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_KEY_RING)

    @property
    def kms_crypto_key_version_crypto_key_path(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_CRYPTO_KEY_PATH)

    @property
    def kms_crypto_key_version_resolved_key_address(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_RESOLVED_KEY_ADDRESS)

    @property
    def kms_crypto_key_version_purpose(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_PURPOSE)

    @property
    def kms_crypto_key_version_algorithm(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_ALGORITHM)

    @property
    def kms_crypto_key_version_protection_level(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_PROTECTION_LEVEL)

    @property
    def kms_crypto_key_version_state(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_STATE)

    @property
    def kms_crypto_key_version_import_posture(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_IMPORT_POSTURE)

    @property
    def kms_crypto_key_version_generate_time(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_GENERATE_TIME)

    @property
    def kms_crypto_key_version_external_key_uri(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_EXTERNAL_KEY_URI)

    @property
    def kms_crypto_key_version_ekm_connection_key_path(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_EKM_CONNECTION_KEY_PATH)

    @property
    def kms_crypto_key_version_external_protection_level_options(self) -> dict[str, object]:
        return self.get(GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_EXTERNAL_PROTECTION_LEVEL_OPTIONS)

    @property
    def kms_crypto_key_version_rotation_period(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_ROTATION_PERIOD)

    @property
    def kms_crypto_key_version_destroy_scheduled_duration(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_DESTROY_SCHEDULED_DURATION)

    @property
    def kms_crypto_key_version_deletion_policy(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_DELETION_POLICY)

    @property
    def kms_crypto_key_version_deletion_policy_state(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_DELETION_POLICY_STATE)

    @property
    def kms_crypto_key_version_posture_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_POSTURE_UNCERTAINTIES)
