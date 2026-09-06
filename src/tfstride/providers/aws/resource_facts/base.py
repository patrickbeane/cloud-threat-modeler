from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.coercion import STATE_DISABLED, STATE_ENABLED
from tfstride.providers.metadata_ownership import ProviderMetadataWriteValidator
from tfstride.providers.resource_facts import ProviderResourceFacts

_AWS_METADATA_WRITE_VALIDATOR = ProviderMetadataWriteValidator.build(
    provider="aws",
    namespace=AwsResourceMetadata,
)


@dataclass(frozen=True, slots=True)
class AwsBaseFacts(ProviderResourceFacts):
    """AWS-owned view over normalized metadata and relationship posture."""

    _metadata_write_validator: ClassVar[ProviderMetadataWriteValidator] = _AWS_METADATA_WRITE_VALIDATOR

    @property
    def name(self) -> str | None:
        return self.get(AwsResourceMetadata.NAME)

    @property
    def resource_name(self) -> str | None:
        return self.name

    @property
    def engine(self) -> str | None:
        return self.get(AwsResourceMetadata.ENGINE)


def _bool_from_state(state: str | None) -> bool | None:
    if state == STATE_ENABLED:
        return True
    if state == STATE_DISABLED:
        return False
    return None
