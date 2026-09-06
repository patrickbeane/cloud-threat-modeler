from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from tfstride.providers.coercion import dedupe
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.metadata_ownership import ProviderMetadataWriteValidator
from tfstride.providers.resource_facts import ProviderResourceFacts
from tfstride.resource_metadata import MetadataField

_GCP_METADATA_WRITE_VALIDATOR = ProviderMetadataWriteValidator.build(
    provider="gcp",
    namespace=GcpResourceMetadata,
)

_REFERENCE_VALUE_FIELDS = (
    GcpResourceMetadata.NAME,
    GcpResourceMetadata.SELF_LINK,
    GcpResourceMetadata.BUCKET_NAME,
    GcpResourceMetadata.SECRET_ID,
    GcpResourceMetadata.SECRET_REFERENCE,
    GcpResourceMetadata.PUBSUB_TOPIC_REFERENCE,
    GcpResourceMetadata.PUBSUB_SUBSCRIPTION_REFERENCE,
    GcpResourceMetadata.BIGQUERY_DATASET_ID,
    GcpResourceMetadata.BIGQUERY_DATASET_REFERENCE,
    GcpResourceMetadata.BIGQUERY_TABLE_ID,
    GcpResourceMetadata.BIGQUERY_TABLE_REFERENCE,
    GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE,
    GcpResourceMetadata.KMS_KEY_RING,
    GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_REFERENCE,
    GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_CRYPTO_KEY_PATH,
    GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_NAME,
    GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_CRYPTO_KEY_REFERENCE,
    GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_KEY_RING,
    GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE,
    GcpResourceMetadata.CLOUD_FUNCTION_REFERENCE,
    GcpResourceMetadata.SERVICE_ACCOUNT_EMAIL,
    GcpResourceMetadata.SERVICE_ACCOUNT_MEMBER,
    GcpResourceMetadata.SERVICE_ACCOUNT_REFERENCE,
    GcpResourceMetadata.ARTIFACT_REGISTRY_REPOSITORY_REFERENCE,
    GcpResourceMetadata.ARTIFACT_REGISTRY_REPOSITORY_PATH,
)
_IAM_TARGET_REFERENCE_FIELDS = (
    GcpResourceMetadata.SERVICE_ACCOUNT_REFERENCE,
    GcpResourceMetadata.BUCKET_NAME,
    GcpResourceMetadata.SECRET_REFERENCE,
    GcpResourceMetadata.PUBSUB_TOPIC_REFERENCE,
    GcpResourceMetadata.PUBSUB_SUBSCRIPTION_REFERENCE,
    GcpResourceMetadata.BIGQUERY_TABLE_REFERENCE,
    GcpResourceMetadata.BIGQUERY_DATASET_REFERENCE,
    GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE,
    GcpResourceMetadata.CLOUD_FUNCTION_REFERENCE,
    GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE,
    GcpResourceMetadata.KMS_KEY_RING,
    GcpResourceMetadata.ARTIFACT_REGISTRY_REPOSITORY_REFERENCE,
)


@dataclass(frozen=True, slots=True)
class GcpBaseFacts(ProviderResourceFacts):
    """GCP-owned view over normalized metadata and relationship posture."""

    _metadata_write_validator: ClassVar[ProviderMetadataWriteValidator] = _GCP_METADATA_WRITE_VALIDATOR

    def optional_bool(self, field: MetadataField[bool]) -> bool | None:
        if not self.resource.has_metadata_value(field):
            return None
        return self.get(field)

    @property
    def project(self) -> str | None:
        return self.get(GcpResourceMetadata.PROJECT)

    @property
    def resource_name(self) -> str | None:
        return self.get(GcpResourceMetadata.NAME)

    @property
    def reference_values(self) -> list[str]:
        values: list[str] = []
        for field in _REFERENCE_VALUE_FIELDS:
            value = self.get(field)
            if value in (None, ""):
                continue
            values.append(str(value))
        return dedupe(values)

    @property
    def target_reference(self) -> str | None:
        for field in _IAM_TARGET_REFERENCE_FIELDS:
            value = self.get(field)
            if value:
                return value
        return None
