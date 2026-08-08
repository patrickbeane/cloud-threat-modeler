from __future__ import annotations

import json
import unittest
from typing import Any

from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.secret_management_evidence import (
    AwsSecretsManagerOperationAuthorization,
)

_ACCOUNT_ID = "111122223333"
_FOREIGN_ACCOUNT_ID = "444455556666"
_SECRET_ARN = f"arn:aws:secretsmanager:us-east-1:{_ACCOUNT_ID}:secret:orders-AbCdEf"
_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/orders-task"
_EXECUTION_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/orders-execution"
_FOREIGN_ROLE_ARN = f"arn:aws:iam::{_FOREIGN_ACCOUNT_ID}:role/orders-task"
_FOREIGN_ROOT_ARN = f"arn:aws:iam::{_FOREIGN_ACCOUNT_ID}:root"
_EXTERNAL_POLICY_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:policy/external-secret-administration"
_MANAGEMENT_OPERATIONS = (
    "secretsmanager:PutSecretValue",
    "secretsmanager:UpdateSecret",
    "secretsmanager:UpdateSecretVersionStage",
    "secretsmanager:DeleteSecret",
)


def _resource(
    resource_type: str,
    name: str,
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _statement(
    effect: str,
    actions: str | list[str],
    resources: str | list[str] = _SECRET_ARN,
    *,
    principal: str | dict[str, Any] | None = None,
    condition: dict[str, Any] | None = None,
) -> dict[str, Any]:
    statement: dict[str, Any] = {
        "Effect": effect,
        "Action": actions,
        "Resource": resources,
    }
    if principal is not None:
        statement["Principal"] = principal if isinstance(principal, dict) else {"AWS": principal}
    if condition is not None:
        statement["Condition"] = condition
    return statement


def _policy(*statements: dict[str, Any]) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": list(statements),
        }
    )


def _secret(
    *,
    arn: str | None = _SECRET_ARN,
    recovery_window_in_days: int = 21,
) -> TerraformResource:
    return _resource(
        "aws_secretsmanager_secret",
        "orders",
        {
            "id": arn,
            "arn": arn,
            "name": "orders",
            "recovery_window_in_days": recovery_window_in_days,
        },
        unknown_values={"arn": True} if arn is None else None,
    )


def _role(
    *statements: dict[str, Any],
    name: str = "orders_task",
    role_arn: str = _ROLE_ARN,
) -> TerraformResource:
    inline_policy = []
    if statements:
        inline_policy = [
            {
                "name": "secret-management",
                "policy": _policy(*statements),
            }
        ]
    return _resource(
        "aws_iam_role",
        name,
        {
            "name": name.replace("_", "-"),
            "arn": role_arn,
            "inline_policy": inline_policy,
        },
    )


def _secret_policy(
    *statements: dict[str, Any],
    name: str = "orders",
    target: str | None = _SECRET_ARN,
    raw_policy: object | None = None,
    unknown_policy: bool = False,
) -> TerraformResource:
    policy = raw_policy if raw_policy is not None else _policy(*statements)
    return _resource(
        "aws_secretsmanager_secret_policy",
        name,
        {
            "secret_arn": target,
            "policy": policy,
        },
        unknown_values={"policy": True} if unknown_policy else None,
    )


def _unresolved_attachment(
    *,
    role_arn: str = _ROLE_ARN,
) -> TerraformResource:
    return _resource(
        "aws_iam_role_policy_attachment",
        "external",
        {
            "role": role_arn,
            "policy_arn": _EXTERNAL_POLICY_ARN,
        },
    )


def _authorizations(
    *resources: TerraformResource,
) -> list[AwsSecretsManagerOperationAuthorization]:
    inventory = AwsNormalizer().normalize(list(resources))
    secret = inventory.get_by_address("aws_secretsmanager_secret.orders")
    assert secret is not None
    return aws_facts(secret).secrets_manager_operation_authorizations


def _authorization(
    resources: list[TerraformResource],
    operation: str,
    *,
    principal_address: str = "aws_iam_role.orders_task",
) -> AwsSecretsManagerOperationAuthorization:
    matches = [
        authorization
        for authorization in _authorizations(*resources)
        if authorization["operation"] == operation and authorization["principal_address"] == principal_address
    ]
    if len(matches) != 1:
        raise AssertionError(f"expected one {operation} authorization for {principal_address}, got {len(matches)}")
    return matches[0]


class AwsSecretsManagerOperationAuthorizationTests(unittest.TestCase):
    def test_same_account_identity_and_direct_resource_policy_bases_are_preserved(
        self,
    ) -> None:
        authorization = _authorization(
            [
                _secret(),
                _role(
                    _statement(
                        "Allow",
                        "secretsmanager:PutSecretValue",
                    ),
                    _statement(
                        "Allow",
                        "secretsmanager:PutSecretValue",
                        condition={"StringEquals": {"aws:PrincipalTag/environment": "production"}},
                    ),
                ),
                _secret_policy(
                    _statement(
                        "Allow",
                        "secretsmanager:PutSecretValue",
                        principal=_ROLE_ARN,
                    )
                ),
            ],
            "secretsmanager:PutSecretValue",
        )

        self.assertEqual(authorization["authorization_state"], "allowed")
        self.assertEqual(
            authorization["authorization_bases"],
            ["identity_policy", "resource_policy_direct"],
        )
        self.assertTrue(authorization["identity_policy_complete"])
        self.assertTrue(authorization["resource_policy_complete"])
        self.assertTrue(authorization["conditional_policy_evidence_present"])
        self.assertFalse(authorization["authorization_requires_condition_evaluation"])
        self.assertEqual(
            authorization["secrets_manager_resource_policy_source_addresses"],
            ["aws_secretsmanager_secret_policy.orders"],
        )
        self.assertEqual(
            authorization["resource_policy_statements"][0]["principal_match"],
            "role",
        )

    def test_same_account_direct_resource_policy_does_not_require_identity_allow(
        self,
    ) -> None:
        authorization = _authorization(
            [
                _secret(),
                _role(),
                _secret_policy(
                    _statement(
                        "Allow",
                        "secretsmanager:UpdateSecret",
                        principal=_ROLE_ARN,
                    )
                ),
            ],
            "secretsmanager:UpdateSecret",
        )

        self.assertEqual(authorization["authorization_state"], "allowed")
        self.assertEqual(
            authorization["authorization_bases"],
            ["resource_policy_direct"],
        )
        self.assertFalse(authorization["identity_policy_required"])
        self.assertFalse(authorization["resource_policy_required"])

    def test_cross_account_authority_requires_identity_and_resource_policy(self) -> None:
        resources = [
            _secret(),
            _role(
                _statement(
                    "Allow",
                    "secretsmanager:DeleteSecret",
                ),
                role_arn=_FOREIGN_ROLE_ARN,
            ),
            _secret_policy(
                _statement(
                    "Allow",
                    "secretsmanager:DeleteSecret",
                    principal=_FOREIGN_ROOT_ARN,
                )
            ),
        ]
        authorization = _authorization(resources, "secretsmanager:DeleteSecret")

        self.assertEqual(authorization["authorization_state"], "allowed")
        self.assertEqual(
            authorization["authorization_bases"],
            ["cross_account_identity_and_resource_policy"],
        )
        self.assertFalse(authorization["same_account"])
        self.assertTrue(authorization["identity_policy_required"])
        self.assertTrue(authorization["resource_policy_required"])
        self.assertEqual(
            authorization["resource_policy_statements"][0]["principal_match"],
            "account",
        )

        resource_only = _authorization(
            [
                _secret(),
                _role(role_arn=_FOREIGN_ROLE_ARN),
                _secret_policy(
                    _statement(
                        "Allow",
                        "secretsmanager:DeleteSecret",
                        principal=_FOREIGN_ROLE_ARN,
                    )
                ),
            ],
            "secretsmanager:DeleteSecret",
        )
        self.assertEqual(resource_only["authorization_state"], "not_allowed")
        self.assertEqual(resource_only["authorization_bases"], [])
        self.assertEqual(
            resource_only["candidate_authorization_bases"],
            ["cross_account_identity_and_resource_policy"],
        )

    def test_explicit_identity_or_resource_policy_deny_wins(self) -> None:
        identity_deny = _authorization(
            [
                _secret(),
                _role(
                    _statement(
                        "Allow",
                        "secretsmanager:DeleteSecret",
                    ),
                    _statement(
                        "Deny",
                        "secretsmanager:DeleteSecret",
                    ),
                ),
            ],
            "secretsmanager:DeleteSecret",
        )
        resource_deny = _authorization(
            [
                _secret(),
                _role(
                    _statement(
                        "Allow",
                        "secretsmanager:PutSecretValue",
                    )
                ),
                _secret_policy(
                    _statement(
                        "Deny",
                        "secretsmanager:PutSecretValue",
                        principal="*",
                    )
                ),
            ],
            "secretsmanager:PutSecretValue",
        )

        self.assertEqual(identity_deny["authorization_state"], "denied")
        self.assertTrue(identity_deny["explicit_deny"])
        self.assertEqual(identity_deny["authorization_bases"], [])
        self.assertEqual(resource_deny["authorization_state"], "denied")
        self.assertTrue(resource_deny["explicit_deny"])

    def test_conditional_allow_without_independent_basis_remains_unknown(self) -> None:
        authorization = _authorization(
            [
                _secret(),
                _role(
                    _statement(
                        "Allow",
                        "secretsmanager:UpdateSecretVersionStage",
                        condition={"StringEquals": {"aws:PrincipalTag/environment": "production"}},
                    )
                ),
            ],
            "secretsmanager:UpdateSecretVersionStage",
        )

        self.assertEqual(authorization["authorization_state"], "unknown")
        self.assertEqual(authorization["authorization_bases"], [])
        self.assertTrue(authorization["authorization_requires_condition_evaluation"])
        self.assertEqual(
            authorization["identity_policy_statements"][0]["conditions"],
            [
                {
                    "operator": "StringEquals",
                    "key": "aws:PrincipalTag/environment",
                    "values": ["production"],
                }
            ],
        )

    def test_unresolved_identity_policy_keeps_every_management_operation_unknown(
        self,
    ) -> None:
        authorizations = _authorizations(
            _secret(),
            _role(),
            _unresolved_attachment(),
        )

        self.assertEqual(
            [authorization["operation"] for authorization in authorizations],
            list(_MANAGEMENT_OPERATIONS),
        )
        self.assertTrue(all(authorization["authorization_state"] == "unknown" for authorization in authorizations))
        self.assertTrue(all(not authorization["identity_policy_complete"] for authorization in authorizations))
        self.assertTrue(
            all(
                authorization["unresolved_attached_policy_arns"] == [_EXTERNAL_POLICY_ARN]
                for authorization in authorizations
            )
        )

    def test_malformed_resource_policy_prevents_identity_allow_from_becoming_exact(
        self,
    ) -> None:
        authorization = _authorization(
            [
                _secret(),
                _role(
                    _statement(
                        "Allow",
                        "secretsmanager:PutSecretValue",
                    )
                ),
                _secret_policy(raw_policy="{"),
            ],
            "secretsmanager:PutSecretValue",
        )

        self.assertEqual(authorization["authorization_state"], "unknown")
        self.assertFalse(authorization["resource_policy_complete"])
        self.assertTrue(authorization["resource_policy_uncertainties"])

    def test_multiple_resource_policy_resources_fail_closed(self) -> None:
        authorization = _authorization(
            [
                _secret(),
                _role(
                    _statement(
                        "Allow",
                        "secretsmanager:UpdateSecret",
                    )
                ),
                _secret_policy(
                    _statement(
                        "Allow",
                        "secretsmanager:UpdateSecret",
                        principal=_ROLE_ARN,
                    ),
                    name="first",
                ),
                _secret_policy(
                    _statement(
                        "Allow",
                        "secretsmanager:UpdateSecret",
                        principal=_ROLE_ARN,
                    ),
                    name="second",
                ),
            ],
            "secretsmanager:UpdateSecret",
        )

        self.assertEqual(authorization["authorization_state"], "unknown")
        self.assertFalse(authorization["resource_policy_complete"])
        self.assertEqual(
            authorization["secrets_manager_resource_policy_source_addresses"],
            [
                "aws_secretsmanager_secret_policy.first",
                "aws_secretsmanager_secret_policy.second",
            ],
        )

    def test_wildcard_principal_allow_is_candidate_evidence_only(self) -> None:
        authorization = _authorization(
            [
                _secret(),
                _role(),
                _secret_policy(
                    _statement(
                        "Allow",
                        "secretsmanager:PutSecretValue",
                        principal="*",
                    )
                ),
            ],
            "secretsmanager:PutSecretValue",
        )

        self.assertEqual(authorization["authorization_state"], "unknown")
        self.assertEqual(authorization["authorization_bases"], [])
        self.assertEqual(
            authorization["candidate_authorization_bases"],
            ["wildcard_resource_policy"],
        )
        self.assertEqual(
            authorization["resource_policy_statements"][0]["principal_match"],
            "wildcard",
        )

    def test_quiet_secret_actions_are_not_operation_authorization_records(self) -> None:
        authorizations = _authorizations(
            _secret(),
            _role(
                _statement(
                    "Allow",
                    [
                        "secretsmanager:GetSecretValue",
                        "secretsmanager:DescribeSecret",
                        "secretsmanager:RestoreSecret",
                        "secretsmanager:RotateSecret",
                    ],
                )
            ),
        )

        self.assertEqual(authorizations, [])


if __name__ == "__main__":
    unittest.main()
