from __future__ import annotations

import unittest

from tests.providers.azure.test_azure_app_service_key_vault_operation_paths import (
    _SYSTEM_PRINCIPAL_ID,
    _VAULT_ID,
    _resource,
    _role_assignment,
    _vault,
)
from tfstride.providers.azure.arm_control_plane_authorization import (
    model_arm_control_plane_action_authority,
)
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_index import (
    AzureDecorationContext,
    AzureResourceIndexBuilder,
)
from tfstride.providers.azure.resource_types import AzureResourceType

_OWNER_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
_CONTRIBUTOR_ID = "b24988ac-6180-42a0-ab88-20f7382dd24c"
_DATA_ACCESS_ADMIN_ID = "8b54135c-b56d-4d72-a534-26097cfdc8d8"
_CUSTOM_ROLE_ID = "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/control-admin"
_ROLE_ASSIGNMENT_WRITE = "Microsoft.Authorization/roleAssignments/write"
_VAULT_WRITE = "Microsoft.KeyVault/vaults/write"


def _custom_role(*, not_actions: tuple[str, ...] = ()):
    return _resource(
        AzureResourceType.ROLE_DEFINITION,
        "control_admin",
        {
            "id": _CUSTOM_ROLE_ID,
            "role_definition_id": _CUSTOM_ROLE_ID,
            "name": "Control Administrator",
            "scope": "/subscriptions/sub-0001",
            "assignable_scopes": ["/subscriptions/sub-0001/resourceGroups/app"],
            "permissions": [
                {
                    "actions": [_ROLE_ASSIGNMENT_WRITE, _VAULT_WRITE],
                    "not_actions": list(not_actions),
                    "data_actions": [],
                    "not_data_actions": [],
                }
            ],
        },
    )


def _custom_assignment(*, condition: str | None = None):
    values: dict[str, object] = {
        "scope": "/subscriptions/sub-0001/resourceGroups/app",
        "role_definition_id": _CUSTOM_ROLE_ID,
        "principal_id": _SYSTEM_PRINCIPAL_ID,
        "principal_type": "ServicePrincipal",
    }
    if condition is not None:
        values["condition"] = condition
        values["condition_version"] = "2.0"
    return _resource(AzureResourceType.ROLE_ASSIGNMENT, "control", values)


def _authority(resources: list, actions: tuple[str, ...]):
    inventory = AzureNormalizer().normalize(resources)
    assignment = next(
        resource for resource in inventory.resources if resource.resource_type == AzureResourceType.ROLE_ASSIGNMENT
    )
    context = AzureDecorationContext(index=AzureResourceIndexBuilder().build(inventory.resources))
    return model_arm_control_plane_action_authority(
        assignment,
        context,
        principal_id=_SYSTEM_PRINCIPAL_ID,
        target_arm_id=_VAULT_ID,
        requested_actions=actions,
    )


class AzureArmControlPlaneAuthorizationTests(unittest.TestCase):
    def test_owner_at_parent_scope_grants_requested_actions(self) -> None:
        result = _authority(
            [
                _vault(rbac_enabled=True),
                _role_assignment(
                    scope="/subscriptions/sub-0001",
                    role_id=_OWNER_ID,
                    role_name="Owner",
                ),
            ],
            (_ROLE_ASSIGNMENT_WRITE, _VAULT_WRITE),
        )

        self.assertEqual(result.state, "granted")
        assert result.grant is not None
        self.assertEqual(
            result.grant["matched_actions"],
            [_ROLE_ASSIGNMENT_WRITE, _VAULT_WRITE],
        )
        self.assertEqual(result.grant["assignment_scope_type"], "subscription")
        self.assertFalse(result.grant["deny_assignments_evaluated"])
        self.assertEqual(
            result.grant["evaluation_basis"],
            "modeled_arm_control_plane_authority",
        )

    def test_contributor_not_actions_exclude_role_assignment_management(self) -> None:
        result = _authority(
            [
                _vault(rbac_enabled=True),
                _role_assignment(
                    role_id=_CONTRIBUTOR_ID,
                    role_name="Contributor",
                ),
            ],
            (_ROLE_ASSIGNMENT_WRITE, _VAULT_WRITE),
        )

        self.assertEqual(result.state, "granted")
        assert result.grant is not None
        self.assertEqual(result.grant["matched_actions"], [_VAULT_WRITE])
        self.assertEqual(result.grant["excluded_actions"], [_ROLE_ASSIGNMENT_WRITE])

    def test_custom_role_actions_not_actions_and_assignable_scope_are_enforced(self) -> None:
        result = _authority(
            [
                _vault(rbac_enabled=True),
                _custom_role(not_actions=(_ROLE_ASSIGNMENT_WRITE,)),
                _custom_assignment(),
            ],
            (_ROLE_ASSIGNMENT_WRITE, _VAULT_WRITE),
        )

        self.assertEqual(result.state, "granted")
        assert result.grant is not None
        self.assertEqual(result.grant["role_kind"], "custom")
        self.assertEqual(result.grant["matched_actions"], [_VAULT_WRITE])
        self.assertEqual(
            result.grant["assignable_scope_compatibility_state"],
            "resolved",
        )

    def test_assignment_condition_and_wrong_principal_fail_closed(self) -> None:
        conditional = _authority(
            [
                _vault(rbac_enabled=True),
                _custom_role(),
                _custom_assignment(condition="@Request[example] StringEquals 'x'"),
            ],
            (_ROLE_ASSIGNMENT_WRITE,),
        )
        unrelated = _authority(
            [
                _vault(rbac_enabled=True),
                _custom_role(),
                _resource(
                    AzureResourceType.ROLE_ASSIGNMENT,
                    "control",
                    {
                        "scope": _VAULT_ID,
                        "role_definition_id": _CUSTOM_ROLE_ID,
                        "principal_id": "other-principal",
                    },
                ),
            ],
            (_ROLE_ASSIGNMENT_WRITE,),
        )

        self.assertEqual(conditional.state, "unknown")
        self.assertTrue(conditional.uncertainties)
        self.assertEqual(unrelated.state, "unrelated")

    def test_data_access_administrator_exposes_role_definition_constraint(self) -> None:
        result = _authority(
            [
                _vault(rbac_enabled=True),
                _role_assignment(
                    role_id=_DATA_ACCESS_ADMIN_ID,
                    role_name="Key Vault Data Access Administrator",
                ),
            ],
            (_ROLE_ASSIGNMENT_WRITE,),
        )

        self.assertEqual(result.state, "granted")
        assert result.grant is not None
        self.assertEqual(
            result.grant["assignment_condition_state"],
            "not_configured",
        )
        self.assertEqual(
            result.grant["role_definition_condition_state"],
            "configured",
        )
        self.assertEqual(
            result.grant["delegation_constraint_kind"],
            "allowed_role_definition_ids",
        )
        self.assertEqual(len(result.grant["allowed_role_definition_ids"]), 8)


if __name__ == "__main__":
    unittest.main()
