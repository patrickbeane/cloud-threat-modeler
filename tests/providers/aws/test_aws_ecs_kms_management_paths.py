from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_ecs_kms_operation_paths import (
    _EXECUTION_ROLE_ARN,
    _KEY_ARNS,
    _ROOT_ARN,
    _TASK_ROLE_ARN,
    _grant,
    _key,
    _policy,
    _resource,
    _role,
    _service,
    _statement,
    _task_definition,
)
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts

_DELEGATION_OPERATIONS = ("kms:CreateGrant", "kms:PutKeyPolicy")
_DISRUPTION_OPERATIONS = (
    "kms:DisableKey",
    "kms:ScheduleKeyDeletion",
)
_QUIET_OPERATIONS = (
    "kms:CancelKeyDeletion",
    "kms:EnableKey",
    "kms:GetKeyPolicy",
    "kms:RotateKeyOnDemand",
)


def _with_lifecycle(
    key: TerraformResource,
    *,
    origin: str,
    origin_unknown: bool = False,
) -> TerraformResource:
    key.values["origin"] = origin
    key.values["deletion_window_in_days"] = 30
    if origin_unknown:
        key.unknown_values["origin"] = True
    return key


def _unresolved_attachment() -> TerraformResource:
    return _resource(
        "aws_iam_role_policy_attachment",
        "external",
        {
            "role": _TASK_ROLE_ARN,
            "policy_arn": "arn:aws:iam::aws:policy/ExternalKmsAdministration",
        },
    )


class AwsEcsKmsManagementPathTests(unittest.TestCase):
    def test_task_role_management_authority_projects_to_service_by_effect(
        self,
    ) -> None:
        all_operations = [
            *_DELEGATION_OPERATIONS,
            *_DISRUPTION_OPERATIONS,
            *_QUIET_OPERATIONS,
        ]
        key = _with_lifecycle(
            _key(
                "data",
                "ENCRYPT_DECRYPT",
                _policy(
                    _statement(
                        "Allow",
                        all_operations,
                        "*",
                        principal=_TASK_ROLE_ARN,
                    ),
                    _statement(
                        "Allow",
                        all_operations,
                        "*",
                        principal=_ROOT_ARN,
                    ),
                    _statement(
                        "Allow",
                        "kms:DisableKey",
                        "*",
                        principal=_EXECUTION_ROLE_ARN,
                    ),
                ),
            ),
            origin="AWS_KMS",
        )
        task_role = _role(
            "orders_task",
            _TASK_ROLE_ARN,
            [
                _statement(
                    "Allow",
                    all_operations,
                    _KEY_ARNS["data"],
                    principal=_TASK_ROLE_ARN,
                )
            ],
        )
        execution_role = _role(
            "orders_execution",
            _EXECUTION_ROLE_ARN,
            [
                _statement(
                    "Allow",
                    "kms:DisableKey",
                    _KEY_ARNS["data"],
                    principal=_EXECUTION_ROLE_ARN,
                )
            ],
        )

        inventory = AwsNormalizer().normalize(
            [
                key,
                task_role,
                execution_role,
                _grant("delegate", "data", ["CreateGrant"]),
                _task_definition(),
                _service(),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert task_definition is not None
        assert service is not None

        paths = aws_facts(task_definition).ecs_kms_management_paths
        self.assertEqual(
            [(path["operation"], path["management_effect"]) for path in paths],
            [
                ("kms:CreateGrant", "delegation"),
                ("kms:PutKeyPolicy", "delegation"),
                ("kms:DisableKey", "disruption"),
                ("kms:ScheduleKeyDeletion", "disruption"),
            ],
        )
        self.assertEqual(
            {path["operation_class"] for path in paths},
            {
                "authorization_administration",
                "disruptive_administration",
                "destructive_administration",
            },
        )
        self.assertTrue(all(path["key_address"] == "aws_kms_key.data" for path in paths))
        self.assertTrue(all(path["key_arn"] == _KEY_ARNS["data"] for path in paths))
        self.assertTrue(all(path["role_address"] == "aws_iam_role.orders_task" for path in paths))
        self.assertNotIn(_EXECUTION_ROLE_ARN, {path["role_arn"] for path in paths})
        self.assertTrue(all(path["authorization_state"] == "allowed" for path in paths))
        self.assertTrue(all(path["deletion_window_in_days"] == 30 for path in paths))
        self.assertTrue(all(path["key_origin"] == "AWS_KMS" for path in paths))

        by_operation = {path["operation"]: path for path in paths}
        create_grant = by_operation["kms:CreateGrant"]
        self.assertEqual(
            create_grant["authorization_bases"],
            ["key_policy_direct", "iam_via_key_policy", "grant"],
        )
        self.assertEqual(create_grant["constraint_state"], "encryption_context")
        self.assertEqual(
            create_grant["grant_constraints"],
            [{"encryption_context_equals": {"service": "orders"}}],
        )
        self.assertEqual(
            by_operation["kms:PutKeyPolicy"]["supported_authorization_bases"],
            ["direct_key_policy", "iam_via_account_principal"],
        )
        self.assertEqual(
            set(by_operation),
            set(_DELEGATION_OPERATIONS) | set(_DISRUPTION_OPERATIONS),
        )

        service_paths = aws_facts(service).ecs_kms_management_paths
        self.assertEqual(len(service_paths), 4)
        self.assertTrue(all(path["workload_address"] == service.address for path in service_paths))
        self.assertTrue(all(path["task_definition_address"] == task_definition.address for path in service_paths))
        self.assertEqual(aws_facts(task_definition).ecs_kms_operation_paths, [])
        self.assertEqual(aws_facts(service).ecs_kms_operation_paths, [])

    def test_imported_material_deletion_requires_compatible_key_origin(
        self,
    ) -> None:
        keys: list[TerraformResource] = []
        for name, origin, origin_unknown in (
            ("data", "EXTERNAL", False),
            ("signing", "AWS_KMS", False),
            ("mac", "EXTERNAL", True),
        ):
            keys.append(
                _with_lifecycle(
                    _key(
                        name,
                        "ENCRYPT_DECRYPT",
                        _policy(
                            _statement(
                                "Allow",
                                "kms:DeleteImportedKeyMaterial",
                                "*",
                                principal=_TASK_ROLE_ARN,
                            )
                        ),
                    ),
                    origin=origin,
                    origin_unknown=origin_unknown,
                )
            )
        task_role = _role(
            "orders_task",
            _TASK_ROLE_ARN,
            [
                _statement(
                    "Allow",
                    "kms:DeleteImportedKeyMaterial",
                    list(_KEY_ARNS.values()),
                    principal=_TASK_ROLE_ARN,
                )
            ],
        )

        inventory = AwsNormalizer().normalize([*keys, task_role, _task_definition(), _service()])
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert task_definition is not None
        assert service is not None

        paths = aws_facts(task_definition).ecs_kms_management_paths
        self.assertEqual(len(paths), 1)
        path = paths[0]
        self.assertEqual(path["key_address"], "aws_kms_key.data")
        self.assertEqual(path["operation"], "kms:DeleteImportedKeyMaterial")
        self.assertEqual(path["management_effect"], "disruption")
        self.assertEqual(path["required_key_origins"], ["EXTERNAL"])
        self.assertEqual(path["key_origin_compatibility_state"], "compatible")

        uncertainties = aws_facts(task_definition).ecs_kms_management_path_uncertainties
        self.assertTrue(any("aws_kms_key.mac origin is unresolved" in uncertainty for uncertainty in uncertainties))
        self.assertFalse(any("aws_kms_key.signing" in uncertainty for uncertainty in uncertainties))
        self.assertEqual(
            aws_facts(service).ecs_kms_management_path_uncertainties,
            uncertainties,
        )

    def test_denied_conditional_and_incomplete_authority_do_not_form_paths(
        self,
    ) -> None:
        conditional_put_policy = _statement(
            "Allow",
            "kms:PutKeyPolicy",
            "*",
            principal=_TASK_ROLE_ARN,
        )
        conditional_put_policy["Condition"] = {"StringEquals": {"aws:PrincipalTag/environment": "production"}}
        data_key = _with_lifecycle(
            _key(
                "data",
                "ENCRYPT_DECRYPT",
                _policy(
                    _statement(
                        "Allow",
                        "kms:DisableKey",
                        "*",
                        principal=_TASK_ROLE_ARN,
                    )
                ),
            ),
            origin="AWS_KMS",
        )
        signing_key = _with_lifecycle(
            _key(
                "signing",
                "ENCRYPT_DECRYPT",
                _policy(conditional_put_policy),
            ),
            origin="AWS_KMS",
        )
        mac_key = _with_lifecycle(
            _key(
                "mac",
                "ENCRYPT_DECRYPT",
                _policy(
                    _statement(
                        "Allow",
                        ["kms:ScheduleKeyDeletion", "kms:RotateKeyOnDemand"],
                        "*",
                        principal=_TASK_ROLE_ARN,
                    )
                ),
            ),
            origin="AWS_KMS",
        )
        task_role = _role(
            "orders_task",
            _TASK_ROLE_ARN,
            [
                _statement(
                    "Deny",
                    "kms:DisableKey",
                    _KEY_ARNS["data"],
                    principal=_TASK_ROLE_ARN,
                )
            ],
        )

        inventory = AwsNormalizer().normalize(
            [
                data_key,
                signing_key,
                mac_key,
                task_role,
                _unresolved_attachment(),
                _task_definition(),
                _service(),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert task_definition is not None
        assert service is not None

        self.assertEqual(aws_facts(task_definition).ecs_kms_management_paths, [])
        uncertainties = aws_facts(task_definition).ecs_kms_management_path_uncertainties
        self.assertTrue(any("kms:PutKeyPolicy" in uncertainty for uncertainty in uncertainties))
        self.assertTrue(any("kms:ScheduleKeyDeletion" in uncertainty for uncertainty in uncertainties))
        self.assertFalse(any("kms:DisableKey" in uncertainty for uncertainty in uncertainties))
        self.assertFalse(any("kms:RotateKeyOnDemand" in uncertainty for uncertainty in uncertainties))
        self.assertEqual(
            aws_facts(service).ecs_kms_management_path_uncertainties,
            uncertainties,
        )

    def test_generic_uncertainty_is_suppressed_when_every_management_operation_is_unavailable(
        self,
    ) -> None:
        management_operations = [
            *_DELEGATION_OPERATIONS,
            *_DISRUPTION_OPERATIONS,
            "kms:DeleteImportedKeyMaterial",
        ]
        key = _with_lifecycle(
            _key(
                "data",
                "ENCRYPT_DECRYPT",
                _policy(
                    _statement(
                        "Allow",
                        management_operations,
                        "*",
                        principal=_ROOT_ARN,
                    )
                ),
            ),
            origin="AWS_KMS",
        )
        task_role = _role(
            "orders_task",
            _TASK_ROLE_ARN,
            [
                _statement(
                    "Deny",
                    management_operations,
                    _KEY_ARNS["data"],
                    principal=_TASK_ROLE_ARN,
                )
            ],
        )
        grant = _grant(
            "unknown_operations",
            "data",
            ["CreateGrant"],
            unknown_values={"operations": True},
        )

        inventory = AwsNormalizer().normalize([key, task_role, grant, _task_definition(), _service()])
        normalized_key = inventory.get_by_address("aws_kms_key.data")
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert normalized_key is not None
        assert task_definition is not None
        assert service is not None

        authorizations = {
            authorization["operation"]: authorization
            for authorization in aws_facts(normalized_key).kms_operation_authorizations
        }
        self.assertEqual(set(authorizations), set(management_operations))
        self.assertTrue(
            all(authorization["authorization_state"] == "denied" for authorization in authorizations.values())
        )
        self.assertTrue(
            any(
                "operations" in uncertainty
                for uncertainty in aws_facts(normalized_key).kms_operation_authorization_uncertainties
            )
        )
        self.assertEqual(aws_facts(task_definition).ecs_kms_management_paths, [])
        self.assertEqual(
            aws_facts(task_definition).ecs_kms_management_path_uncertainties,
            [],
        )
        self.assertEqual(aws_facts(service).ecs_kms_management_paths, [])
        self.assertEqual(
            aws_facts(service).ecs_kms_management_path_uncertainties,
            [],
        )

    def test_unknown_grant_operations_remain_management_path_uncertain(
        self,
    ) -> None:
        key = _with_lifecycle(
            _key(
                "data",
                "ENCRYPT_DECRYPT",
                _policy(
                    _statement(
                        "Allow",
                        "kms:CreateGrant",
                        "*",
                        principal=_ROOT_ARN,
                    )
                ),
            ),
            origin="AWS_KMS",
        )
        task_role = _role("orders_task", _TASK_ROLE_ARN, [])
        grant = _grant(
            "unknown_operations",
            "data",
            ["CreateGrant"],
            unknown_values={"operations": True},
        )

        inventory = AwsNormalizer().normalize([key, task_role, grant, _task_definition(), _service()])
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert task_definition is not None
        assert service is not None

        self.assertEqual(aws_facts(task_definition).ecs_kms_management_paths, [])
        uncertainties = aws_facts(task_definition).ecs_kms_management_path_uncertainties
        self.assertTrue(any("grant" in uncertainty.casefold() for uncertainty in uncertainties))
        self.assertTrue(any("operations" in uncertainty for uncertainty in uncertainties))
        self.assertEqual(
            aws_facts(service).ecs_kms_management_path_uncertainties,
            uncertainties,
        )
