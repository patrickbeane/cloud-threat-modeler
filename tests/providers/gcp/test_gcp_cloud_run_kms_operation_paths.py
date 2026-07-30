from __future__ import annotations

import unittest
from typing import Any

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.models import NormalizedResource, ResourceInventory, TerraformResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_decoration.cloud_run_kms_operation_paths import (
    ModelCloudRunKmsOperationPathsStage,
)
from tfstride.providers.gcp.resource_decorator import GcpResourceDecorator
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_PROJECT = "tfstride-demo"
_FOREIGN_PROJECT = "foreign-project"
_EMAIL = f"orders@{_PROJECT}.iam.gserviceaccount.com"
_MEMBER = f"serviceAccount:{_EMAIL}"
_OTHER_MEMBER = f"serviceAccount:other@{_PROJECT}.iam.gserviceaccount.com"
_RING = f"projects/{_PROJECT}/locations/global/keyRings/application"
_OTHER_RING = f"projects/{_PROJECT}/locations/us-central1/keyRings/secondary"
_FOREIGN_RING = f"projects/{_FOREIGN_PROJECT}/locations/global/keyRings/application"


def _cloud_run(
    *,
    address: str = "google_cloud_run_v2_service.orders",
    service_account: str = _EMAIL,
    version: int = 2,
    public: bool = True,
) -> TerraformResource:
    if version == 1:
        return _terraform_resource(
            address,
            GcpResourceType.CLOUD_RUN_SERVICE,
            {
                "name": address.rsplit(".", 1)[-1],
                "project": _PROJECT,
                "location": "us-central1",
                "metadata": [{"annotations": {"run.googleapis.com/ingress": ("all" if public else "internal")}}],
                "template": [
                    {
                        "spec": [
                            {
                                "service_account_name": service_account,
                            }
                        ]
                    }
                ],
            },
        )
    return _terraform_resource(
        address,
        GcpResourceType.CLOUD_RUN_V2_SERVICE,
        {
            "name": address.rsplit(".", 1)[-1],
            "project": _PROJECT,
            "location": "us-central1",
            "ingress": ("INGRESS_TRAFFIC_ALL" if public else "INGRESS_TRAFFIC_INTERNAL_ONLY"),
            "template": [{"service_account": service_account}],
        },
    )


def _key(
    name: str,
    purpose: str,
    *,
    ring: str = _RING,
    unknown_purpose: bool = False,
) -> TerraformResource:
    return _terraform_resource(
        f"google_kms_crypto_key.{name}",
        GcpResourceType.KMS_CRYPTO_KEY,
        {
            "id": f"{ring}/cryptoKeys/{name}",
            "name": name,
            "key_ring": ring,
            "purpose": purpose,
        },
        unknown_values={"purpose": True} if unknown_purpose else None,
    )


def _version(
    name: str,
    algorithm: str,
    *,
    state: str = "ENABLED",
    ring: str = _RING,
) -> TerraformResource:
    key_path = f"{ring}/cryptoKeys/{name}"
    version_path = f"{key_path}/cryptoKeyVersions/1"
    return _terraform_resource(
        f"google_kms_crypto_key_version.{name}",
        GcpResourceType.KMS_CRYPTO_KEY_VERSION,
        {
            "crypto_key": f"google_kms_crypto_key.{name}.id",
            "id": version_path,
            "name": version_path,
            "state": state,
            "algorithm": algorithm,
            "protection_level": "SOFTWARE",
            "generate_time": "2026-07-19T00:00:00Z",
        },
    )


def _custom_role(
    name: str,
    permissions: list[str],
) -> TerraformResource:
    role_id = f"{name}Crypto"
    return _terraform_resource(
        f"google_project_iam_custom_role.{name}",
        GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
        {
            "project": _PROJECT,
            "role_id": role_id,
            "name": f"projects/{_PROJECT}/roles/{role_id}",
            "permissions": permissions,
        },
    )


def _project_member(
    name: str,
    role: str,
    *,
    project: str = _PROJECT,
    member: str = _MEMBER,
    condition: dict[str, str] | None = None,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "project": project,
        "role": role,
        "member": member,
    }
    if condition is not None:
        values["condition"] = [condition]
    return _terraform_resource(
        f"google_project_iam_member.{name}",
        GcpResourceType.PROJECT_IAM_MEMBER,
        values,
        unknown_values=unknown_values,
    )


def _ring_member(
    name: str,
    role: str,
    *,
    ring: str = _RING,
    member: str = _MEMBER,
) -> TerraformResource:
    return _terraform_resource(
        f"google_kms_key_ring_iam_member.{name}",
        GcpResourceType.KMS_KEY_RING_IAM_MEMBER,
        {
            "key_ring_id": ring,
            "role": role,
            "member": member,
        },
    )


def _key_member(
    name: str,
    key_name: str,
    role: str,
    *,
    member: str = _MEMBER,
    condition: dict[str, str] | None = None,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "crypto_key_id": f"google_kms_crypto_key.{key_name}.id",
        "role": role,
        "member": member,
    }
    if condition is not None:
        values["condition"] = [condition]
    return _terraform_resource(
        f"google_kms_crypto_key_iam_member.{name}",
        GcpResourceType.KMS_CRYPTO_KEY_IAM_MEMBER,
        values,
        unknown_values=unknown_values,
    )


def _key_binding(
    name: str,
    key_name: str,
    role: str,
    *,
    members: list[str] | None = None,
) -> TerraformResource:
    return _terraform_resource(
        f"google_kms_crypto_key_iam_binding.{name}",
        GcpResourceType.KMS_CRYPTO_KEY_IAM_BINDING,
        {
            "crypto_key_id": f"google_kms_crypto_key.{key_name}.id",
            "role": role,
            "members": members or [_MEMBER],
        },
    )


def _workload(
    inventory: ResourceInventory,
    address: str = "google_cloud_run_v2_service.orders",
) -> NormalizedResource:
    resource = inventory.get_by_address(address)
    assert resource is not None
    return resource


class GcpCloudRunKmsOperationPathTests(unittest.TestCase):
    def test_runtime_member_projects_decrypt_sign_and_mac_with_version_evidence(
        self,
    ) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run(),
                _key("data", "ENCRYPT_DECRYPT"),
                _version("data", "GOOGLE_SYMMETRIC_ENCRYPTION"),
                _key("signing", "ASYMMETRIC_SIGN"),
                _version("signing", "EC_SIGN_P256_SHA256"),
                _key("mac", "MAC"),
                _version("mac", "HMAC_SHA256", state="DISABLED"),
                _project_member(
                    "runtime_decrypter",
                    "roles/cloudkms.cryptoKeyDecrypter",
                ),
                _key_member(
                    "runtime_signer",
                    "signing",
                    "roles/cloudkms.signer",
                ),
                _key_member(
                    "runtime_mac_signer",
                    "mac",
                    "roles/cloudkms.signer",
                ),
            ]
        )

        paths = gcp_facts(_workload(inventory)).cloud_run_kms_operation_paths
        self.assertEqual(
            [path["operation_class"] for path in paths],
            ["decrypt", "mac_generation", "sign"],
        )
        by_class = {path["operation_class"]: path for path in paths}

        decrypt = by_class["decrypt"]
        self.assertEqual(decrypt["service_account_member"], _MEMBER)
        self.assertEqual(decrypt["key_address"], "google_kms_crypto_key.data")
        self.assertEqual(
            decrypt["operation"],
            "cloudkms.cryptoKeyVersions.useToDecrypt",
        )
        self.assertEqual(decrypt["scope_type"], "project")
        self.assertEqual(decrypt["scope"], _PROJECT)
        self.assertEqual(decrypt["authorization_state"], "granted")
        self.assertEqual(decrypt["management_state"], "unambiguous")

        signing = by_class["sign"]
        self.assertEqual(signing["key_purpose"], "ASYMMETRIC_SIGN")
        self.assertEqual(signing["scope_type"], "crypto_key")
        self.assertEqual(
            signing["scope"],
            f"{_RING}/cryptoKeys/signing",
        )
        self.assertEqual(signing["matched_permissions"], [signing["operation"]])

        mac = by_class["mac_generation"]
        self.assertEqual(mac["key_purpose"], "MAC")
        self.assertEqual(mac["operation"], signing["operation"])
        self.assertEqual(mac["key_versions"][0]["algorithm"], "HMAC_SHA256")
        self.assertEqual(mac["key_versions"][0]["state"], "DISABLED")
        self.assertEqual(mac["key_versions"][0]["version_identity_state"], "resolved")
        self.assertEqual(
            mac["key_versions"][0]["version_resource_name"],
            f"{_RING}/cryptoKeys/mac/cryptoKeyVersions/1",
        )
        self.assertEqual(
            mac["key_version_evidence_scope"],
            "modeled_versions_of_crypto_key",
        )
        self.assertFalse(mac["iam_scope_is_key_version"])
        self.assertNotEqual(mac["scope_type"], "crypto_key_version")

    def test_project_and_key_ring_grants_fan_only_to_exact_modeled_keys(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run(),
                _key("primary", "ENCRYPT_DECRYPT"),
                _key("secondary", "ENCRYPT_DECRYPT", ring=_OTHER_RING),
                _key("foreign", "ENCRYPT_DECRYPT", ring=_FOREIGN_RING),
                _project_member(
                    "project_decrypter",
                    "roles/cloudkms.cryptoKeyDecrypter",
                ),
                _ring_member(
                    "ring_decrypter",
                    "roles/cloudkms.cryptoKeyDecrypter",
                ),
            ]
        )

        paths = gcp_facts(_workload(inventory)).cloud_run_kms_operation_paths
        by_source: dict[str, set[str]] = {}
        for path in paths:
            by_source.setdefault(str(path["iam_resource_address"]), set()).add(str(path["key_address"]))

        self.assertEqual(
            by_source["google_project_iam_member.project_decrypter"],
            {
                "google_kms_crypto_key.primary",
                "google_kms_crypto_key.secondary",
            },
        )
        self.assertEqual(
            by_source["google_kms_key_ring_iam_member.ring_decrypter"],
            {"google_kms_crypto_key.primary"},
        )
        self.assertFalse(any(path["key_address"] == "google_kms_crypto_key.foreign" for path in paths))

    def test_deterministic_custom_role_preserves_exact_permission_evidence(self) -> None:
        role_name = f"projects/{_PROJECT}/roles/runtimeCrypto"
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run(),
                _key("data", "ENCRYPT_DECRYPT"),
                _custom_role(
                    "runtime",
                    [
                        "cloudkms.cryptoKeyVersions.useToDecrypt",
                        "cloudkms.cryptoKeyVersions.useToEncrypt",
                        "storage.objects.get",
                    ],
                ),
                _project_member(
                    "runtime_custom",
                    role_name,
                ),
            ]
        )

        paths = gcp_facts(_workload(inventory)).cloud_run_kms_operation_paths
        self.assertEqual(len(paths), 1)
        path_record = paths[0]
        self.assertEqual(path_record["operation_class"], "decrypt")
        self.assertEqual(path_record["role_kind"], "custom")
        self.assertEqual(path_record["role_resolution_state"], "resolved")
        self.assertEqual(
            path_record["role_definition_address"],
            "google_project_iam_custom_role.runtime",
        )
        self.assertEqual(
            path_record["custom_role_permissions"],
            [
                "cloudkms.cryptoKeyVersions.useToDecrypt",
                "cloudkms.cryptoKeyVersions.useToEncrypt",
                "storage.objects.get",
            ],
        )
        self.assertEqual(
            path_record["matched_permissions"],
            ["cloudkms.cryptoKeyVersions.useToDecrypt"],
        )

    def test_conditional_and_ambiguous_iam_do_not_become_paths(self) -> None:
        condition = {
            "title": "business-hours",
            "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
        }
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run(),
                _key("conditional", "ENCRYPT_DECRYPT"),
                _key("ambiguous", "ENCRYPT_DECRYPT"),
                _key_member(
                    "conditional_decrypter",
                    "conditional",
                    "roles/cloudkms.cryptoKeyDecrypter",
                    condition=condition,
                ),
                _key_binding(
                    "ambiguous_decrypters",
                    "ambiguous",
                    "roles/cloudkms.cryptoKeyDecrypter",
                ),
                _key_member(
                    "ambiguous_decrypter",
                    "ambiguous",
                    "roles/cloudkms.cryptoKeyDecrypter",
                ),
            ]
        )

        facts = gcp_facts(_workload(inventory))
        self.assertEqual(facts.cloud_run_kms_operation_paths, [])
        self.assertTrue(
            any(
                "authorization_state=conditional" in uncertainty
                for uncertainty in facts.cloud_run_kms_operation_path_uncertainties
            )
        )
        self.assertTrue(
            any(
                "management_state=ambiguous" in uncertainty
                for uncertainty in facts.cloud_run_kms_operation_path_uncertainties
            )
        )

    def test_delegated_quiet_and_other_identity_permissions_stay_quiet(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run(),
                _key("data", "ENCRYPT_DECRYPT"),
                _key("signing", "ASYMMETRIC_SIGN"),
                _key_member(
                    "delegated",
                    "data",
                    "roles/cloudkms.cryptoKeyDecrypterViaDelegation",
                ),
                _key_member(
                    "encrypter",
                    "data",
                    "roles/cloudkms.cryptoKeyEncrypter",
                    unknown_values={"condition": True},
                ),
                _key_member(
                    "verifier",
                    "signing",
                    "roles/cloudkms.verifier",
                ),
                _key_member(
                    "other_decrypter",
                    "data",
                    "roles/cloudkms.cryptoKeyDecrypter",
                    member=_OTHER_MEMBER,
                ),
            ]
        )

        facts = gcp_facts(_workload(inventory))
        self.assertEqual(facts.cloud_run_kms_operation_paths, [])
        self.assertEqual(facts.cloud_run_kms_operation_path_uncertainties, [])

    def test_partially_unknown_binding_members_remain_path_uncertain(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run(),
                _key("data", "ENCRYPT_DECRYPT"),
                _terraform_resource(
                    "google_kms_crypto_key_iam_binding.partial_members",
                    GcpResourceType.KMS_CRYPTO_KEY_IAM_BINDING,
                    {
                        "crypto_key_id": "google_kms_crypto_key.data.id",
                        "role": "roles/cloudkms.cryptoKeyDecrypter",
                        "members": [_OTHER_MEMBER, None],
                    },
                    unknown_values={"members": [False, True]},
                ),
            ]
        )
        workload = _workload(inventory)
        key = inventory.get_by_address("google_kms_crypto_key.data")
        binding = inventory.get_by_address("google_kms_crypto_key_iam_binding.partial_members")
        assert key is not None
        assert binding is not None
        self.assertEqual(gcp_facts(binding).bindings[0]["members_state"], "unknown")
        self.assertEqual(gcp_facts(binding).bindings[0]["members"], [_OTHER_MEMBER])
        self.assertTrue(
            any(
                "IAM members are unresolved" in uncertainty
                for uncertainty in gcp_facts(key).kms_iam_posture_uncertainties
            )
        )

        key_path = f"{_RING}/cryptoKeys/data"
        gcp_facts(key).set(
            GcpResourceMetadata.KMS_IAM_GRANTS,
            [
                {
                    "source": binding.address,
                    "source_type": binding.resource_type,
                    "role": "roles/cloudkms.cryptoKeyDecrypter",
                    "role_kind": "predefined",
                    "role_resolution_state": "modeled_subset",
                    "modeled_kms_permissions": ["cloudkms.cryptoKeyVersions.useToDecrypt"],
                    "scope_effective_permissions": ["cloudkms.cryptoKeyVersions.useToDecrypt"],
                    "members": [_OTHER_MEMBER],
                    "crypto_key_address": key.address,
                    "crypto_key": key_path,
                    "project": _PROJECT,
                    "key_ring": _RING,
                    "scope_type": "crypto_key",
                    "scope": key_path,
                    "condition_state": "not_configured",
                    "authorization_state": "granted",
                    "management_state": "unambiguous",
                }
            ],
        )
        workload_facts = gcp_facts(workload)
        workload_facts.set_cloud_run_kms_operation_paths([])
        workload_facts.set(
            GcpResourceMetadata.CLOUD_RUN_KMS_OPERATION_PATH_UNCERTAINTIES,
            [],
        )
        GcpResourceDecorator(stages=[ModelCloudRunKmsOperationPathsStage()]).decorate(list(inventory.resources))

        self.assertEqual(workload_facts.cloud_run_kms_operation_paths, [])
        self.assertTrue(
            any(
                "IAM members are unresolved" in uncertainty
                for uncertainty in workload_facts.cloud_run_kms_operation_path_uncertainties
            )
        )

    def test_unknown_member_and_unknown_key_purpose_remain_uncertain(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run(),
                _key("data", "ENCRYPT_DECRYPT"),
                _key("signing", "ASYMMETRIC_SIGN", unknown_purpose=True),
                _key_member(
                    "unknown_member",
                    "data",
                    "roles/cloudkms.cryptoKeyDecrypter",
                    unknown_values={"member": True},
                ),
                _key_member(
                    "runtime_signer",
                    "signing",
                    "roles/cloudkms.signer",
                ),
            ]
        )

        facts = gcp_facts(_workload(inventory))
        self.assertEqual(facts.cloud_run_kms_operation_paths, [])
        self.assertTrue(
            any(
                "IAM members are unresolved" in uncertainty
                for uncertainty in facts.cloud_run_kms_operation_path_uncertainties
            )
        )
        self.assertTrue(
            any(
                "purpose is unresolved" in uncertainty
                for uncertainty in facts.cloud_run_kms_operation_path_uncertainties
            )
        )

    def test_v1_private_workload_still_receives_authorization_path(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run(
                    address="google_cloud_run_service.orders",
                    version=1,
                    public=False,
                ),
                _key("data", "ENCRYPT_DECRYPT"),
                _project_member(
                    "runtime_decrypter",
                    "roles/cloudkms.cryptoKeyDecrypter",
                ),
            ]
        )

        workload = _workload(inventory, "google_cloud_run_service.orders")
        self.assertFalse(workload.public_exposure)
        self.assertEqual(
            [path["operation_class"] for path in gcp_facts(workload).cloud_run_kms_operation_paths],
            ["decrypt"],
        )


if __name__ == "__main__":
    unittest.main()
