from __future__ import annotations

import json
import unittest
from typing import Any, Literal

from tfstride.models import (
    TerraformReferenceProvenance,
    TerraformReferenceResolution,
    TerraformReferenceResolutionState,
    TerraformReferenceTarget,
    TerraformResource,
)
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts

_ACCOUNT_ID = "111122223333"
_TASK_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/orders-task"
_EXECUTION_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/orders-execution"
_TABLE_ARN = f"arn:aws:dynamodb:us-east-1:{_ACCOUNT_ID}:table/orders"


def _resource(
    resource_type: str,
    name: str,
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
    reference_resolutions: tuple[
        TerraformReferenceResolution,
        ...,
    ] = (),
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
        reference_resolutions=reference_resolutions,
    )


def _symbolic_resolution(
    path: tuple[str | int, ...],
    reference: str,
    *target_addresses: str,
    state: TerraformReferenceResolutionState = (TerraformReferenceResolutionState.SYMBOLIC),
) -> TerraformReferenceResolution:
    return TerraformReferenceResolution(
        path=path,
        state=state,
        provenance=TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
        references=(reference,),
        targets=tuple(
            TerraformReferenceTarget(
                address=address,
                reference=reference,
            )
            for address in target_addresses
        ),
    )


def _table(
    *,
    pitr: Literal["enabled", "disabled", "omitted", "unknown"] = "enabled",
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": "orders",
        "name": "orders",
        "arn": _TABLE_ARN,
    }
    unknown_values: dict[str, Any] = {}
    if pitr == "enabled":
        values["point_in_time_recovery"] = [
            {
                "enabled": True,
                "recovery_period_in_days": 14,
            }
        ]
    elif pitr == "disabled":
        values["point_in_time_recovery"] = [{"enabled": False}]
    elif pitr == "unknown":
        unknown_values["point_in_time_recovery"] = True
    return _resource(
        "aws_dynamodb_table",
        "orders",
        values,
        unknown_values=unknown_values,
    )


def _statement(
    effect: str,
    actions: str | list[str],
    resources: str | list[str],
    *,
    condition: dict[str, Any] | None = None,
) -> dict[str, Any]:
    statement: dict[str, Any] = {
        "Effect": effect,
        "Action": actions,
        "Resource": resources,
    }
    if condition is not None:
        statement["Condition"] = condition
    return statement


def _role(
    name: str,
    arn: str | None,
    statements: list[dict[str, Any]],
) -> TerraformResource:
    return _resource(
        "aws_iam_role",
        name,
        {
            "name": name,
            "arn": arn,
            "inline_policy": [
                {
                    "name": "dynamodb-access",
                    "policy": json.dumps(
                        {
                            "Version": "2012-10-17",
                            "Statement": statements,
                        }
                    ),
                }
            ],
        },
    )


def _task_definition() -> TerraformResource:
    return _resource(
        "aws_ecs_task_definition",
        "orders",
        {
            "family": "orders",
            "revision": 1,
            "container_definitions": "[]",
            "task_role_arn": _TASK_ROLE_ARN,
            "execution_role_arn": _EXECUTION_ROLE_ARN,
        },
    )


def _service() -> TerraformResource:
    return _resource(
        "aws_ecs_service",
        "orders",
        {
            "name": "orders",
            "task_definition": "orders:1",
        },
    )


def _task_paths(
    resources: list[TerraformResource],
) -> tuple[list[dict[str, Any]], list[str]]:
    inventory = AwsNormalizer().normalize(resources)
    task = inventory.get_by_address("aws_ecs_task_definition.orders")
    assert task is not None
    facts = aws_facts(task)
    return (
        [dict(path) for path in facts.ecs_dynamodb_item_deletion_paths],
        facts.ecs_dynamodb_item_deletion_path_uncertainties,
    )


class AwsEcsDynamoDbItemDeletionPathTests(unittest.TestCase):
    def test_operation_exact_paths_are_projected_without_inventing_items(
        self,
    ) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            [
                                "dynamodb:DeleteItem",
                                "dynamodb:PartiQLDelete",
                                "dynamodb:BatchWriteItem",
                                "dynamodb:PutItem",
                            ],
                            _TABLE_ARN,
                        )
                    ],
                ),
                _task_definition(),
                _service(),
            ]
        )
        task = inventory.get_by_address("aws_ecs_task_definition.orders")
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert task is not None
        assert service is not None

        task_paths = aws_facts(task).ecs_dynamodb_item_deletion_paths
        service_paths = aws_facts(service).ecs_dynamodb_item_deletion_paths
        self.assertEqual(len(task_paths), 3)
        self.assertEqual(len(service_paths), 3)

        expected = {
            "dynamodb:DeleteItem": ("item_deletion", "delete_item"),
            "dynamodb:PartiQLDelete": (
                "item_deletion",
                "partiql_delete",
            ),
            "dynamodb:BatchWriteItem": (
                "batch_item_deletion",
                "batch_write_delete",
            ),
        }
        for path in service_paths:
            operation = path["operation"]
            self.assertIn(operation, expected)
            self.assertEqual(
                (path["operation_class"], path["internal_operation"]),
                expected[operation],
            )
            self.assertEqual(path["matched_actions"], [operation])
            self.assertEqual(path["workload_address"], service.address)
            self.assertEqual(path["workload_type"], service.resource_type)
            self.assertEqual(path["task_definition_address"], task.address)
            self.assertEqual(path["role_kind"], "ecs_task_role")
            self.assertEqual(path["credential_context"], "workload_runtime")
            self.assertEqual(path["role_reference"], _TASK_ROLE_ARN)
            self.assertEqual(path["role_arn"], _TASK_ROLE_ARN)
            self.assertEqual(
                path["dynamodb_table_address"],
                "aws_dynamodb_table.orders",
            )
            self.assertEqual(path["dynamodb_table_name"], "orders")
            self.assertEqual(
                path["dynamodb_table_reference"],
                _TABLE_ARN,
            )
            self.assertEqual(path["dynamodb_table_arn"], _TABLE_ARN)
            self.assertEqual(
                path["target_granularity"],
                "table_item_namespace",
            )
            self.assertEqual(
                path["target_scope"],
                "exact_table_item_namespace",
            )
            self.assertEqual(
                path["target_model_evidence_addresses"],
                ["aws_dynamodb_table.orders"],
            )
            self.assertEqual(path["authorization_state"], "allowed")
            self.assertTrue(path["role_policy_complete"])
            self.assertFalse(path["explicit_deny"])
            self.assertFalse(path["conditional_evaluation_required"])
            self.assertEqual(path["resource_scopes"], ["exact_table"])
            self.assertEqual(path["internet_facing_load_balancers"], [])
            self.assertNotIn("item_key", path)
            self.assertNotIn("partition_key", path)
            self.assertNotIn("sort_key", path)

            statement = path["policy_statements"][0]
            self.assertEqual(statement["matched_actions"], [operation])
            self.assertEqual(statement["matching_resources"], [_TABLE_ARN])
            self.assertEqual(statement["resource_scopes"], ["exact_table"])
            self.assertEqual(statement["conditions"], [])
            self.assertFalse(statement["conditional"])

            recovery = path["recovery_evidence"]
            self.assertEqual(
                recovery["recovery_evidence_scope"],
                "dynamodb_point_in_time_recovery",
            )
            self.assertEqual(recovery["pitr_state"], "enabled")
            self.assertTrue(recovery["pitr_enabled"])
            self.assertEqual(recovery["pitr_recovery_period_days"], 14)

        batch = next(path for path in service_paths if path["operation"] == "dynamodb:BatchWriteItem")
        self.assertTrue(batch["batch_write_includes_put_capability"])

    def test_exact_symbolic_task_role_reference_emits_path(self) -> None:
        role_reference = "aws_iam_role.orders_task.arn"
        task = _resource(
            "aws_ecs_task_definition",
            "orders",
            {
                "family": "orders",
                "revision": 1,
                "container_definitions": "[]",
            },
            unknown_values={"task_role_arn": True},
            reference_resolutions=(
                _symbolic_resolution(
                    ("task_role_arn",),
                    role_reference,
                    "aws_iam_role.orders_task",
                ),
            ),
        )
        paths, uncertainties = _task_paths(
            [
                _table(),
                _role(
                    "orders_task",
                    None,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:DeleteItem",
                            _TABLE_ARN,
                        )
                    ],
                ),
                task,
            ]
        )

        self.assertEqual(len(paths), 1)
        self.assertEqual(
            paths[0]["role_reference"],
            role_reference,
        )
        self.assertIsNone(paths[0]["role_arn"])
        self.assertEqual(uncertainties, [])

    def test_exact_symbolic_table_policy_reference_emits_path(
        self,
    ) -> None:
        table_reference = "aws_dynamodb_table.orders.arn"
        table = _resource(
            "aws_dynamodb_table",
            "orders",
            {
                "id": "orders",
                "name": "orders",
            },
            unknown_values={"arn": True},
        )
        role = _role(
            "orders_task",
            _TASK_ROLE_ARN,
            [
                _statement(
                    "Allow",
                    "dynamodb:DeleteItem",
                    table_reference,
                )
            ],
        )
        role.reference_resolutions = (
            _symbolic_resolution(
                ("inline_policy", 0, "policy"),
                table_reference,
                "aws_dynamodb_table.orders",
            ),
        )
        paths, uncertainties = _task_paths(
            [
                table,
                role,
                _task_definition(),
            ]
        )

        self.assertEqual(len(paths), 1)
        path = paths[0]
        self.assertEqual(
            path["dynamodb_table_reference"],
            table_reference,
        )
        self.assertIsNone(path["dynamodb_table_arn"])
        self.assertEqual(path["policy_resources"], [table_reference])
        self.assertEqual(
            path["policy_statements"][0]["matching_resources"],
            [table_reference],
        )
        self.assertEqual(uncertainties, [])

    def test_ambiguous_symbolic_role_and_table_references_are_uncertain(
        self,
    ) -> None:
        role_reference = "aws_iam_role.orders_task.arn"
        ambiguous_task = _resource(
            "aws_ecs_task_definition",
            "orders",
            {
                "family": "orders",
                "revision": 1,
                "container_definitions": "[]",
            },
            unknown_values={"task_role_arn": True},
            reference_resolutions=(
                _symbolic_resolution(
                    ("task_role_arn",),
                    role_reference,
                    "aws_iam_role.orders_task",
                    "aws_iam_role.other_task",
                    state=TerraformReferenceResolutionState.AMBIGUOUS,
                ),
            ),
        )
        role_paths, role_uncertainties = _task_paths(
            [
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:DeleteItem",
                            _TABLE_ARN,
                        )
                    ],
                ),
                _role(
                    "other_task",
                    f"arn:aws:iam::{_ACCOUNT_ID}:role/other-task",
                    [],
                ),
                ambiguous_task,
            ]
        )
        self.assertEqual(role_paths, [])
        self.assertTrue(role_uncertainties)

        unresolved_task = _resource(
            "aws_ecs_task_definition",
            "orders",
            {
                "family": "orders",
                "revision": 1,
                "container_definitions": "[]",
            },
            unknown_values={"task_role_arn": True},
            reference_resolutions=(
                _symbolic_resolution(
                    ("task_role_arn",),
                    role_reference,
                    state=(TerraformReferenceResolutionState.UNRESOLVED),
                ),
            ),
        )
        unresolved_paths, unresolved_uncertainties = _task_paths(
            [
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:DeleteItem",
                            _TABLE_ARN,
                        )
                    ],
                ),
                unresolved_task,
            ]
        )
        self.assertEqual(unresolved_paths, [])
        self.assertTrue(unresolved_uncertainties)

        table_reference = "aws_dynamodb_table.orders.arn"
        role = _role(
            "orders_task",
            _TASK_ROLE_ARN,
            [
                _statement(
                    "Allow",
                    "dynamodb:DeleteItem",
                    table_reference,
                )
            ],
        )
        role.reference_resolutions = (
            _symbolic_resolution(
                ("inline_policy", 0, "policy"),
                table_reference,
                "aws_dynamodb_table.orders",
                "aws_dynamodb_table.archive",
                state=TerraformReferenceResolutionState.AMBIGUOUS,
            ),
        )
        archive = _resource(
            "aws_dynamodb_table",
            "archive",
            {
                "id": "archive",
                "name": "archive",
                "arn": (f"arn:aws:dynamodb:us-east-1:{_ACCOUNT_ID}:table/archive"),
            },
        )
        table_paths, table_uncertainties = _task_paths(
            [
                _table(),
                archive,
                role,
                _task_definition(),
            ]
        )
        self.assertEqual(table_paths, [])
        self.assertTrue(
            any("ambiguous or unresolved exact table ancestry" in uncertainty for uncertainty in table_uncertainties)
        )

    def test_raw_symbolic_looking_table_string_without_provenance_is_quiet(
        self,
    ) -> None:
        table_reference = "aws_dynamodb_table.orders.arn"
        paths, uncertainties = _task_paths(
            [
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:DeleteItem",
                            table_reference,
                        )
                    ],
                ),
                _task_definition(),
            ]
        )

        self.assertEqual(paths, [])
        self.assertEqual(uncertainties, [])

    def test_underlying_delete_item_authority_covers_transactions(
        self,
    ) -> None:
        delete_paths, _ = _task_paths(
            [
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:DeleteItem",
                            _TABLE_ARN,
                        )
                    ],
                ),
                _task_definition(),
            ]
        )
        synthetic_paths, synthetic_uncertainties = _task_paths(
            [
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:TransactWriteItems",
                            _TABLE_ARN,
                        )
                    ],
                ),
                _task_definition(),
            ]
        )

        self.assertEqual(
            [path["operation"] for path in delete_paths],
            ["dynamodb:DeleteItem"],
        )
        self.assertEqual(synthetic_paths, [])
        self.assertEqual(synthetic_uncertainties, [])

    def test_unrelated_deny_and_condition_do_not_suppress_delete_item(
        self,
    ) -> None:
        paths, uncertainties = _task_paths(
            [
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:DeleteItem",
                            _TABLE_ARN,
                        ),
                        _statement(
                            "Deny",
                            "dynamodb:PutItem",
                            _TABLE_ARN,
                        ),
                        _statement(
                            "Allow",
                            "dynamodb:PartiQLDelete",
                            _TABLE_ARN,
                            condition={
                                "ForAllValues:StringEquals": {
                                    "dynamodb:LeadingKeys": ["tenant-123"],
                                }
                            },
                        ),
                    ],
                ),
                _task_definition(),
            ]
        )

        self.assertEqual(
            [path["operation"] for path in paths],
            ["dynamodb:DeleteItem"],
        )
        self.assertTrue(any("dynamodb:PartiQLDelete" in uncertainty for uncertainty in uncertainties))

    def test_incidental_conditional_allow_does_not_override_unconditional_basis(
        self,
    ) -> None:
        paths, uncertainties = _task_paths(
            [
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:DeleteItem",
                            _TABLE_ARN,
                        ),
                        _statement(
                            "Allow",
                            "dynamodb:DeleteItem",
                            _TABLE_ARN,
                            condition={
                                "ForAllValues:StringEquals": {
                                    "dynamodb:LeadingKeys": ["tenant-123"],
                                }
                            },
                        ),
                    ],
                ),
                _task_definition(),
            ]
        )

        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["operation"], "dynamodb:DeleteItem")
        self.assertEqual(len(paths[0]["policy_statements"]), 1)
        self.assertFalse(paths[0]["conditional_evaluation_required"])
        self.assertTrue(any("conditional identity-policy evidence" in uncertainty for uncertainty in uncertainties))

    def test_operation_deny_incomplete_policy_and_wildcard_scope_fail_closed(
        self,
    ) -> None:
        denied_paths, denied_uncertainties = _task_paths(
            [
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:DeleteItem",
                            _TABLE_ARN,
                        ),
                        _statement(
                            "Deny",
                            "dynamodb:DeleteItem",
                            _TABLE_ARN,
                        ),
                    ],
                ),
                _task_definition(),
            ]
        )
        self.assertEqual(denied_paths, [])
        self.assertFalse(any("dynamodb:DeleteItem authority" in uncertainty for uncertainty in denied_uncertainties))

        attachment = _resource(
            "aws_iam_role_policy_attachment",
            "external",
            {
                "role": _TASK_ROLE_ARN,
                "policy_arn": "arn:aws:iam::aws:policy/ExternalDelete",
            },
        )
        incomplete_paths, incomplete_uncertainties = _task_paths(
            [
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:DeleteItem",
                            _TABLE_ARN,
                        )
                    ],
                ),
                attachment,
                _task_definition(),
            ]
        )
        self.assertEqual(incomplete_paths, [])
        self.assertTrue(incomplete_uncertainties)

        wildcard_paths, wildcard_uncertainties = _task_paths(
            [
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:DeleteItem",
                            f"arn:aws:dynamodb:us-east-1:{_ACCOUNT_ID}:table/*",
                        )
                    ],
                ),
                _task_definition(),
            ]
        )
        self.assertEqual(wildcard_paths, [])
        self.assertTrue(
            any("does not identify an exact table" in uncertainty for uncertainty in wildcard_uncertainties)
        )

    def test_execution_role_authority_is_excluded(self) -> None:
        paths, uncertainties = _task_paths(
            [
                _table(),
                _resource(
                    "aws_iam_role",
                    "orders_task",
                    {
                        "name": "orders_task",
                        "arn": _TASK_ROLE_ARN,
                    },
                ),
                _role(
                    "orders_execution",
                    _EXECUTION_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            [
                                "dynamodb:DeleteItem",
                                "dynamodb:PartiQLDelete",
                                "dynamodb:BatchWriteItem",
                            ],
                            _TABLE_ARN,
                        )
                    ],
                ),
                _task_definition(),
            ]
        )

        self.assertEqual(paths, [])
        self.assertEqual(uncertainties, [])

    def test_pitr_recovery_states_remain_provider_native(self) -> None:
        expected = {
            "enabled": ("enabled", True, 14),
            "disabled": ("disabled", False, None),
            "omitted": ("not_configured", False, None),
            "unknown": ("unknown", None, None),
        }
        for pitr, expected_recovery in expected.items():
            with self.subTest(pitr=pitr):
                paths, uncertainties = _task_paths(
                    [
                        _table(
                            pitr=pitr,  # type: ignore[arg-type]
                        ),
                        _role(
                            "orders_task",
                            _TASK_ROLE_ARN,
                            [
                                _statement(
                                    "Allow",
                                    "dynamodb:DeleteItem",
                                    _TABLE_ARN,
                                )
                            ],
                        ),
                        _task_definition(),
                    ]
                )
                self.assertEqual(len(paths), 1)
                recovery = paths[0]["recovery_evidence"]
                self.assertEqual(
                    (
                        recovery["pitr_state"],
                        recovery["pitr_enabled"],
                        recovery["pitr_recovery_period_days"],
                    ),
                    expected_recovery,
                )
                if pitr == "unknown":
                    self.assertTrue(recovery["uncertainties"])
                    self.assertTrue(uncertainties)
                else:
                    self.assertEqual(recovery["uncertainties"], [])


if __name__ == "__main__":
    unittest.main()
