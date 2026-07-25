from __future__ import annotations

from typing import Any

from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.resource_facts.base import AwsBaseFacts, _bool_from_state


class AwsDynamoDbFacts(AwsBaseFacts):
    __slots__ = ()

    @property
    def dynamodb_table_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.DYNAMODB_TABLE_ARN)

    @property
    def dynamodb_kms_key_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.DYNAMODB_KMS_KEY_ARN)

    @property
    def dynamodb_encryption_ownership_state(self) -> str | None:
        return self.get(AwsResourceMetadata.DYNAMODB_ENCRYPTION_OWNERSHIP_STATE)

    @property
    def dynamodb_encryption_configuration_state(self) -> str | None:
        return self.get(AwsResourceMetadata.DYNAMODB_ENCRYPTION_CONFIGURATION_STATE)

    @property
    def dynamodb_pitr_state(self) -> str | None:
        return self.get(AwsResourceMetadata.DYNAMODB_PITR_STATE)

    @property
    def dynamodb_pitr_enabled(self) -> bool | None:
        return _bool_from_state(self.dynamodb_pitr_state)

    @property
    def dynamodb_pitr_recovery_period_days(self) -> int | None:
        return self.get(AwsResourceMetadata.DYNAMODB_PITR_RECOVERY_PERIOD_DAYS)

    @property
    def dynamodb_deletion_protection_state(self) -> str | None:
        return self.get(AwsResourceMetadata.DYNAMODB_DELETION_PROTECTION_STATE)

    @property
    def dynamodb_deletion_protection_enabled(self) -> bool | None:
        return _bool_from_state(self.dynamodb_deletion_protection_state)

    @property
    def dynamodb_replicas(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.DYNAMODB_REPLICAS)

    @property
    def dynamodb_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.DYNAMODB_POSTURE_UNCERTAINTIES)
