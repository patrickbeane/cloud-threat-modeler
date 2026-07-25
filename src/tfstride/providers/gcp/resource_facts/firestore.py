from __future__ import annotations

from typing import Any

from tfstride.providers.coercion import STATE_CONFIGURED, STATE_DISABLED, STATE_ENABLED, STATE_NOT_CONFIGURED
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts.base import GcpBaseFacts


class GcpFirestoreFacts(GcpBaseFacts):
    __slots__ = ()

    @property
    def firestore_database_type(self) -> str | None:
        return self.get(GcpResourceMetadata.FIRESTORE_DATABASE_TYPE)

    @property
    def firestore_location(self) -> str | None:
        return self.get(GcpResourceMetadata.FIRESTORE_LOCATION)

    @property
    def firestore_cmek_key_name(self) -> str | None:
        return self.get(GcpResourceMetadata.FIRESTORE_CMEK_KEY_NAME)

    @property
    def firestore_cmek_state(self) -> str | None:
        return self.get(GcpResourceMetadata.FIRESTORE_CMEK_STATE)

    @property
    def firestore_customer_managed_encryption(self) -> bool | None:
        state = self.firestore_cmek_state
        if state == STATE_CONFIGURED:
            return True
        if state == STATE_NOT_CONFIGURED:
            return False
        return None

    @property
    def firestore_cmek_config(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.FIRESTORE_CMEK_CONFIG)

    @property
    def firestore_pitr_enablement(self) -> str | None:
        return self.get(GcpResourceMetadata.FIRESTORE_PITR_ENABLEMENT)

    @property
    def firestore_pitr_state(self) -> str | None:
        return self.get(GcpResourceMetadata.FIRESTORE_PITR_STATE)

    @property
    def firestore_pitr_enabled(self) -> bool | None:
        state = self.firestore_pitr_state
        if state == STATE_ENABLED:
            return True
        if state == STATE_DISABLED:
            return False
        return None

    @property
    def firestore_delete_protection_state(self) -> str | None:
        return self.get(GcpResourceMetadata.FIRESTORE_DELETE_PROTECTION_STATE)

    @property
    def firestore_delete_protection_enablement(self) -> str | None:
        return self.get(GcpResourceMetadata.FIRESTORE_DELETE_PROTECTION_ENABLEMENT)

    @property
    def firestore_delete_protection_enabled(self) -> bool | None:
        state = self.firestore_delete_protection_enablement
        if state == STATE_ENABLED:
            return True
        if state == STATE_DISABLED:
            return False
        return None

    @property
    def firestore_terraform_deletion_policy(self) -> str | None:
        return self.get(GcpResourceMetadata.FIRESTORE_TERRAFORM_DELETION_POLICY)

    @property
    def firestore_terraform_deletion_policy_state(self) -> str | None:
        return self.get(GcpResourceMetadata.FIRESTORE_TERRAFORM_DELETION_POLICY_STATE)

    @property
    def firestore_posture_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.FIRESTORE_POSTURE_UNCERTAINTIES)
