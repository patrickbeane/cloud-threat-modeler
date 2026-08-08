from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts.base import GcpBaseFacts
from tfstride.providers.gcp.secret_management_evidence import GcpSecretManagerIamGrant


class GcpSecretManagerFacts(GcpBaseFacts):
    __slots__ = ()

    @property
    def secret_id(self) -> str | None:
        return self.get(GcpResourceMetadata.SECRET_ID)

    @property
    def secret_manager_replication_mode(self) -> str | None:
        return self.get(GcpResourceMetadata.SECRET_MANAGER_REPLICATION_MODE)

    @property
    def secret_manager_kms_key_names(self) -> list[str]:
        return self.get(GcpResourceMetadata.SECRET_MANAGER_KMS_KEY_NAMES)

    @property
    def secret_manager_replication(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.SECRET_MANAGER_REPLICATION)

    @property
    def secret_manager_ttl(self) -> str | None:
        return self.get(GcpResourceMetadata.SECRET_MANAGER_TTL)

    @property
    def secret_manager_expire_time(self) -> str | None:
        return self.get(GcpResourceMetadata.SECRET_MANAGER_EXPIRE_TIME)

    @property
    def secret_manager_version_destroy_ttl(self) -> str | None:
        return self.get(GcpResourceMetadata.SECRET_MANAGER_VERSION_DESTROY_TTL)

    @property
    def secret_manager_posture_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.SECRET_MANAGER_POSTURE_UNCERTAINTIES)

    @property
    def secret_manager_iam_grants(self) -> list[GcpSecretManagerIamGrant]:
        return self.get(GcpResourceMetadata.SECRET_MANAGER_IAM_GRANTS)

    @property
    def secret_manager_iam_posture_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.SECRET_MANAGER_IAM_POSTURE_UNCERTAINTIES)

    def set_secret_manager_iam_posture(
        self,
        *,
        grants: Sequence[GcpSecretManagerIamGrant],
        uncertainties: Sequence[str],
    ) -> None:
        self.set(GcpResourceMetadata.SECRET_MANAGER_IAM_GRANTS, list(grants))
        self.set(
            GcpResourceMetadata.SECRET_MANAGER_IAM_POSTURE_UNCERTAINTIES,
            list(uncertainties),
        )
