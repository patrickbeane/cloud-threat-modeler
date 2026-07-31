from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from tfstride.providers.azure.key_vault_evidence import AzureKeyVaultAuthorizationGrant
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_facts.base import AzureBaseFacts


class AzureKeyVaultFacts(AzureBaseFacts):
    __slots__ = ()

    @property
    def key_vault_id(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_ID)

    @property
    def key_vault_uri(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_URI)

    @property
    def key_vault_reference(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_REFERENCE)

    @property
    def resolved_key_vault_address(self) -> str | None:
        return self.get(AzureResourceMetadata.RESOLVED_KEY_VAULT_ADDRESS)

    @property
    def key_vault_secret_name(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_SECRET_NAME)

    @property
    def key_vault_secret_uri(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_SECRET_URI)

    @property
    def key_vault_secret_versionless_uri(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_SECRET_VERSIONLESS_URI)

    @property
    def key_vault_secret_version(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_SECRET_VERSION)

    @property
    def key_vault_secret_resource_id(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_SECRET_RESOURCE_ID)

    @property
    def key_vault_key_name(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_KEY_NAME)

    @property
    def key_vault_key_uri(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_KEY_URI)

    @property
    def key_vault_key_versionless_uri(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_KEY_VERSIONLESS_URI)

    @property
    def key_vault_key_version(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_KEY_VERSION)

    @property
    def key_vault_key_resource_id(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_KEY_RESOURCE_ID)

    @property
    def key_vault_key_versionless_resource_id(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_KEY_VERSIONLESS_RESOURCE_ID)

    @property
    def key_vault_key_identity_state(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_KEY_IDENTITY_STATE)

    @property
    def key_vault_key_expiration_state(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_KEY_EXPIRATION_STATE)

    @property
    def key_vault_key_authorization_grants(self) -> list[AzureKeyVaultAuthorizationGrant]:
        return self.get(AzureResourceMetadata.KEY_VAULT_KEY_AUTHORIZATION_GRANTS)

    @property
    def key_vault_key_authorization_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.KEY_VAULT_KEY_AUTHORIZATION_UNCERTAINTIES)

    @property
    def key_vault_expiration_date(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_EXPIRATION_DATE)

    @property
    def key_vault_not_before_date(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_NOT_BEFORE_DATE)

    @property
    def key_vault_certificate_validity_months(self) -> int | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_CERTIFICATE_VALIDITY_MONTHS)

    @property
    def key_vault_key_type(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_KEY_TYPE)

    @property
    def key_vault_key_size(self) -> int | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_KEY_SIZE)

    @property
    def key_vault_key_curve(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_KEY_CURVE)

    @property
    def key_vault_key_ops(self) -> list[str]:
        return self.get(AzureResourceMetadata.KEY_VAULT_KEY_OPS)

    @property
    def key_vault_rotation_policy(self) -> dict[str, Any]:
        return self.get(AzureResourceMetadata.KEY_VAULT_ROTATION_POLICY)

    @property
    def key_vault_rotation_policy_expire_after(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_ROTATION_POLICY_EXPIRE_AFTER)

    @property
    def key_vault_rotation_policy_notify_before_expiry(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_ROTATION_POLICY_NOTIFY_BEFORE_EXPIRY)

    @property
    def key_vault_rotation_policy_automatic_time_after_creation(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_ROTATION_POLICY_AUTOMATIC_TIME_AFTER_CREATION)

    @property
    def key_vault_rotation_policy_automatic_time_before_expiry(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_ROTATION_POLICY_AUTOMATIC_TIME_BEFORE_EXPIRY)

    @property
    def key_vault_key_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.KEY_VAULT_KEY_POSTURE_UNCERTAINTIES)

    @property
    def purge_protection_enabled(self) -> bool | None:
        return self.optional_bool(AzureResourceMetadata.PURGE_PROTECTION_ENABLED)

    @property
    def rbac_authorization_enabled(self) -> bool | None:
        return self.optional_bool(AzureResourceMetadata.RBAC_AUTHORIZATION_ENABLED)

    @property
    def key_vault_access_policies(self) -> list[dict[str, Any]]:
        return self.get(AzureResourceMetadata.KEY_VAULT_ACCESS_POLICIES)

    @property
    def key_vault_role_assignments(self) -> list[dict[str, Any]]:
        return self.get(AzureResourceMetadata.KEY_VAULT_ROLE_ASSIGNMENTS)

    @property
    def key_vault_related_resource_addresses(self) -> list[str]:
        return self.get(AzureResourceMetadata.KEY_VAULT_RELATED_RESOURCE_ADDRESSES)

    @property
    def key_vault_network_ip_rules(self) -> list[str]:
        return self.get(AzureResourceMetadata.KEY_VAULT_NETWORK_IP_RULES)

    @property
    def key_vault_network_subnet_ids(self) -> list[str]:
        return self.get(AzureResourceMetadata.KEY_VAULT_NETWORK_SUBNET_IDS)

    @property
    def key_vault_network_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.KEY_VAULT_NETWORK_UNCERTAINTIES)

    @property
    def key_vault_authorization_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.KEY_VAULT_AUTHORIZATION_UNCERTAINTIES)

    @property
    def key_vault_recovery_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.KEY_VAULT_RECOVERY_UNCERTAINTIES)

    @property
    def key_vault_lifecycle_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.KEY_VAULT_LIFECYCLE_UNCERTAINTIES)

    @property
    def key_vault_identity_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.KEY_VAULT_IDENTITY_UNCERTAINTIES)

    def set_key_vault_uri(self, uri: str) -> None:
        self.set(AzureResourceMetadata.KEY_VAULT_URI, uri)

    def set_key_vault_secret_identity(
        self,
        *,
        versionless_uri: str | None = None,
        secret_uri: str | None = None,
        version: str | None = None,
    ) -> None:
        if versionless_uri is not None and self.key_vault_secret_versionless_uri is None:
            self.set(AzureResourceMetadata.KEY_VAULT_SECRET_VERSIONLESS_URI, versionless_uri)
        if secret_uri is not None and self.key_vault_secret_uri is None:
            self.set(AzureResourceMetadata.KEY_VAULT_SECRET_URI, secret_uri)
        if version is not None and self.key_vault_secret_version is None:
            self.set(AzureResourceMetadata.KEY_VAULT_SECRET_VERSION, version)

    def set_key_vault_key_identity(
        self,
        *,
        versionless_uri: str | None = None,
        key_uri: str | None = None,
        version: str | None = None,
        versionless_resource_id: str | None = None,
        resource_id: str | None = None,
    ) -> None:
        if self.key_vault_key_identity_state == "ambiguous":
            return
        candidates = (
            (
                AzureResourceMetadata.KEY_VAULT_KEY_VERSIONLESS_URI,
                self.key_vault_key_versionless_uri,
                versionless_uri,
                "versionless Key Vault key URI",
            ),
            (
                AzureResourceMetadata.KEY_VAULT_KEY_URI,
                self.key_vault_key_uri,
                key_uri,
                "versioned Key Vault key URI",
            ),
            (
                AzureResourceMetadata.KEY_VAULT_KEY_VERSION,
                self.key_vault_key_version,
                version,
                "Key Vault key version",
            ),
            (
                AzureResourceMetadata.KEY_VAULT_KEY_VERSIONLESS_RESOURCE_ID,
                self.key_vault_key_versionless_resource_id,
                versionless_resource_id,
                "versionless Key Vault key resource ID",
            ),
            (
                AzureResourceMetadata.KEY_VAULT_KEY_RESOURCE_ID,
                self.key_vault_key_resource_id,
                resource_id,
                "versioned Key Vault key resource ID",
            ),
        )
        for field, current, candidate, label in candidates:
            if candidate is None:
                continue
            if current is not None and current.casefold() != candidate.casefold():
                self.mark_key_vault_key_identity_ambiguous(f"conflicting {label} values are present")
                return
            if current is None:
                self.set(field, candidate)

        if self.key_vault_key_identity_state == "partial" or self.key_vault_key_identity_state is None:
            if any(
                value is not None
                for value in (
                    self.key_vault_key_uri,
                    self.key_vault_key_versionless_uri,
                    self.key_vault_key_resource_id,
                    self.key_vault_key_versionless_resource_id,
                )
            ):
                self.set(AzureResourceMetadata.KEY_VAULT_KEY_IDENTITY_STATE, "resolved")

    def mark_key_vault_key_identity_ambiguous(self, uncertainty: str) -> None:
        for field in (
            AzureResourceMetadata.KEY_VAULT_KEY_NAME,
            AzureResourceMetadata.KEY_VAULT_KEY_URI,
            AzureResourceMetadata.KEY_VAULT_KEY_VERSIONLESS_URI,
            AzureResourceMetadata.KEY_VAULT_KEY_VERSION,
            AzureResourceMetadata.KEY_VAULT_KEY_RESOURCE_ID,
            AzureResourceMetadata.KEY_VAULT_KEY_VERSIONLESS_RESOURCE_ID,
        ):
            self.set(field, None)
        self.set(AzureResourceMetadata.KEY_VAULT_KEY_IDENTITY_STATE, "ambiguous")
        self.append(AzureResourceMetadata.KEY_VAULT_IDENTITY_UNCERTAINTIES, uncertainty)

    def extend_key_vault_identity_uncertainties(self, uncertainties: Sequence[str | None]) -> None:
        self.extend(AzureResourceMetadata.KEY_VAULT_IDENTITY_UNCERTAINTIES, uncertainties)

    def set_key_vault_key_authorization_posture(
        self,
        *,
        grants: Sequence[AzureKeyVaultAuthorizationGrant],
        uncertainties: Sequence[str],
    ) -> None:
        self.set(AzureResourceMetadata.KEY_VAULT_KEY_AUTHORIZATION_GRANTS, list(grants))
        self.set(
            AzureResourceMetadata.KEY_VAULT_KEY_AUTHORIZATION_UNCERTAINTIES,
            list(uncertainties),
        )

    def set_resolved_key_vault_address(self, address: str) -> None:
        self.set(AzureResourceMetadata.RESOLVED_KEY_VAULT_ADDRESS, address)

    def add_key_vault_related_resource_address(self, address: str) -> None:
        self.append(AzureResourceMetadata.KEY_VAULT_RELATED_RESOURCE_ADDRESSES, address)

    def add_key_vault_access_policy(self, policy: dict[str, Any]) -> None:
        policies = self.key_vault_access_policies
        if policy not in policies:
            policies.append(policy)
            self.set(AzureResourceMetadata.KEY_VAULT_ACCESS_POLICIES, policies)

    def set_key_vault_role_assignments(self, assignments: Sequence[dict[str, Any]]) -> None:
        self.set(AzureResourceMetadata.KEY_VAULT_ROLE_ASSIGNMENTS, list(assignments))

    def add_key_vault_role_assignment(self, assignment: dict[str, Any]) -> None:
        assignments = self.key_vault_role_assignments
        if assignment not in assignments:
            assignments.append(assignment)
            self.set(AzureResourceMetadata.KEY_VAULT_ROLE_ASSIGNMENTS, assignments)

    def extend_key_vault_network_uncertainties(self, uncertainties: Sequence[str | None]) -> None:
        self.extend(AzureResourceMetadata.KEY_VAULT_NETWORK_UNCERTAINTIES, uncertainties)

    def extend_key_vault_authorization_uncertainties(
        self,
        uncertainties: Sequence[str | None],
    ) -> None:
        self.extend(AzureResourceMetadata.KEY_VAULT_AUTHORIZATION_UNCERTAINTIES, uncertainties)
