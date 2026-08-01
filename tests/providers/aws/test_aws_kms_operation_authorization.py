from __future__ import annotations

import json
import unittest
from typing import Any

from tfstride.models import TerraformResource
from tfstride.providers.aws.kms_evidence import AwsKmsOperationAuthorization
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts

_ACCOUNT_ID = "111122223333"
_FOREIGN_ACCOUNT_ID = "444455556666"
_KEY_ID = "11111111-1111-1111-1111-111111111111"
_OTHER_KEY_ID = "22222222-2222-2222-2222-222222222222"
_KEY_ARN = f"arn:aws:kms:us-east-1:{_ACCOUNT_ID}:key/{_KEY_ID}"
_OTHER_KEY_ARN = f"arn:aws:kms:us-east-1:{_ACCOUNT_ID}:key/{_OTHER_KEY_ID}"
_ALIAS_ARN = f"arn:aws:kms:us-east-1:{_ACCOUNT_ID}:alias/orders"
_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/orders-task"
_FOREIGN_ROLE_ARN = f"arn:aws:iam::{_FOREIGN_ACCOUNT_ID}:role/orders-task"
_ACCOUNT_ROOT_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:root"
_ADMIN_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/kms-admin"


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
    resources: str | list[str],
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
        statement["Principal"] = principal
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


def _admin_key_statement() -> dict[str, Any]:
    return _statement(
        "Allow",
        "kms:*",
        "*",
        principal={"AWS": _ADMIN_ROLE_ARN},
    )


def _delegation_statement(
    actions: str | list[str] = "kms:*",
    *,
    condition: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _statement(
        "Allow",
        actions,
        "*",
        principal={"AWS": _ACCOUNT_ROOT_ARN},
        condition=condition,
    )


def _direct_statement(
    actions: str | list[str] = "kms:Decrypt",
    *,
    effect: str = "Allow",
    principal: str = _ROLE_ARN,
    condition: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _statement(
        effect,
        actions,
        "*",
        principal={"AWS": principal},
        condition=condition,
    )


def _key(
    policy: object,
    *,
    name: str = "data",
    key_arn: str = _KEY_ARN,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    key_id = key_arn.rsplit("/", 1)[-1]
    return _resource(
        "aws_kms_key",
        name,
        {
            "id": key_id,
            "key_id": key_id,
            "arn": key_arn,
            "key_usage": "ENCRYPT_DECRYPT",
            "key_spec": "SYMMETRIC_DEFAULT",
            "policy": policy,
        },
        unknown_values=unknown_values,
    )


def _role(
    *statements: dict[str, Any],
    name: str = "orders_task",
    role_arn: str = _ROLE_ARN,
    unknown_inline_policy: bool = False,
    unknown_inline_name: bool = False,
    malformed_policy: bool = False,
) -> TerraformResource:
    inline_policy: list[dict[str, Any]] = []
    if statements or malformed_policy:
        inline_policy = [
            {
                "name": "kms-use",
                "policy": "{" if malformed_policy else _policy(*statements),
            }
        ]
    unknown_values = None
    if unknown_inline_policy:
        unknown_values = {"inline_policy": [{"policy": True}]}
    elif unknown_inline_name:
        unknown_values = {"inline_policy": [{"name": True}]}
    return _resource(
        "aws_iam_role",
        name,
        {
            "name": name.replace("_", "-"),
            "arn": role_arn,
            "inline_policy": inline_policy,
        },
        unknown_values=unknown_values,
    )


def _unresolved_attachment() -> TerraformResource:
    return _resource(
        "aws_iam_role_policy_attachment",
        "external",
        {
            "role": _ROLE_ARN,
            "policy_arn": "arn:aws:iam::aws:policy/ExternalKmsAccess",
        },
    )


def _grant(
    *,
    operations: list[str] | None = None,
    constraints: list[dict[str, Any]] | None = None,
    grantee_principal: str = _ROLE_ARN,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": "grant-orders-runtime",
        "grant_id": "grant-orders-runtime",
        "name": "orders-runtime",
        "key_id": "aws_kms_key.data.key_id",
        "grantee_principal": grantee_principal,
        "operations": operations or ["Decrypt"],
        "retire_on_delete": False,
    }
    if constraints is not None:
        values["constraints"] = constraints
    return _resource(
        "aws_kms_grant",
        "orders_runtime",
        values,
        unknown_values=unknown_values,
    )


def _standalone_key_policy(policy: str) -> TerraformResource:
    return _resource(
        "aws_kms_key_policy",
        "data",
        {
            "id": "policy-data",
            "key_id": "aws_kms_key.data.key_id",
            "policy": policy,
            "bypass_policy_lockout_safety_check": False,
        },
    )


def _authorizations(
    *resources: TerraformResource,
) -> list[AwsKmsOperationAuthorization]:
    inventory = AwsNormalizer().normalize(list(resources))
    key = inventory.get_by_address("aws_kms_key.data")
    assert key is not None
    return aws_facts(key).kms_operation_authorizations


def _authorization(
    resources: list[TerraformResource],
    operation: str,
) -> AwsKmsOperationAuthorization:
    matches = [
        authorization for authorization in _authorizations(*resources) if authorization["operation"] == operation
    ]
    if len(matches) != 1:
        raise AssertionError(f"expected one {operation} authorization, got {len(matches)}")
    return matches[0]


class AwsKmsOperationAuthorizationTests(unittest.TestCase):
    def test_complete_key_policy_can_directly_authorize_same_account_role(self) -> None:
        authorization = _authorization(
            [
                _key(_policy(_admin_key_statement(), _direct_statement())),
                _role(),
            ],
            "kms:Decrypt",
        )

        self.assertEqual(authorization["authorization_state"], "allowed")
        self.assertEqual(
            authorization["authorization_bases"],
            ["direct_key_policy"],
        )
        self.assertTrue(authorization["key_policy_complete"])
        self.assertTrue(authorization["identity_policy_complete"])
        self.assertEqual(
            authorization["key_policy_source_addresses"],
            ["aws_kms_key.data"],
        )
        self.assertEqual(
            authorization["identity_policy_source_addresses"],
            ["aws_iam_role.orders_task"],
        )
        self.assertEqual(
            authorization["key_policy_statements"][0]["principal_match"],
            "role",
        )

    def test_unknown_inline_policy_name_does_not_hide_known_policy_evidence(self) -> None:
        authorization = _authorization(
            [
                _key(_policy(_admin_key_statement(), _direct_statement())),
                _role(
                    _statement("Allow", "kms:Encrypt", _KEY_ARN),
                    unknown_inline_name=True,
                ),
            ],
            "kms:Decrypt",
        )

        self.assertEqual(authorization["authorization_state"], "allowed")
        self.assertTrue(authorization["identity_policy_complete"])

    def test_account_principal_delegation_makes_exact_iam_allow_effective(self) -> None:
        authorization = _authorization(
            [
                _key(_policy(_delegation_statement())),
                _role(_statement("Allow", "kms:Decrypt", _KEY_ARN)),
            ],
            "kms:Decrypt",
        )

        self.assertEqual(authorization["authorization_state"], "allowed")
        self.assertEqual(
            authorization["authorization_bases"],
            ["iam_via_account_principal"],
        )
        self.assertEqual(
            authorization["identity_policy_statements"][0]["matching_resources"],
            [_KEY_ARN],
        )
        self.assertEqual(
            authorization["key_policy_statements"][0]["source_kind"],
            "account_principal_delegation",
        )

    def test_delegated_operation_remains_unknown_when_role_policy_is_unresolved(self) -> None:
        authorization = _authorization(
            [
                _key(_policy(_delegation_statement("kms:Decrypt"))),
                _role(),
                _unresolved_attachment(),
            ],
            "kms:Decrypt",
        )

        self.assertEqual(authorization["authorization_state"], "unknown")
        self.assertEqual(authorization["authorization_bases"], [])
        self.assertEqual(
            authorization["candidate_authorization_bases"],
            ["iam_via_account_principal"],
        )
        self.assertFalse(authorization["identity_policy_complete"])
        self.assertEqual(
            authorization["unresolved_attached_policy_arns"],
            ["arn:aws:iam::aws:policy/ExternalKmsAccess"],
        )

    def test_wildcard_key_policy_allow_remains_explicit_unknown_candidate(self) -> None:
        wildcard_allow = _statement(
            "Allow",
            "kms:Decrypt",
            "*",
            principal="*",
        )
        authorization = _authorization(
            [
                _key(_policy(_admin_key_statement(), wildcard_allow)),
                _role(),
            ],
            "kms:Decrypt",
        )

        self.assertEqual(authorization["authorization_state"], "unknown")
        self.assertTrue(authorization["key_policy_complete"])
        self.assertEqual(authorization["authorization_bases"], [])
        self.assertEqual(
            authorization["candidate_authorization_bases"],
            ["wildcard_key_policy"],
        )
        self.assertEqual(
            authorization["key_policy_statements"][0]["source_kind"],
            "wildcard_key_policy",
        )
        self.assertEqual(
            authorization["key_policy_statements"][0]["principal_match"],
            "wildcard",
        )

    def test_iam_allow_without_key_policy_delegation_is_not_effective(self) -> None:
        authorization = _authorization(
            [
                _key(_policy(_admin_key_statement())),
                _role(_statement("Allow", "kms:Decrypt", _KEY_ARN)),
            ],
            "kms:Decrypt",
        )

        self.assertEqual(authorization["authorization_state"], "not_allowed")
        self.assertEqual(authorization["authorization_bases"], [])
        self.assertEqual(
            authorization["candidate_authorization_bases"],
            ["iam_via_account_principal"],
        )

    def test_exact_grant_authorizes_role_and_preserves_encryption_context(self) -> None:
        authorization = _authorization(
            [
                _key(_policy(_admin_key_statement())),
                _role(),
                _grant(
                    constraints=[
                        {
                            "encryption_context_equals": {
                                "service": "orders",
                            }
                        }
                    ]
                ),
            ],
            "kms:Decrypt",
        )

        self.assertEqual(authorization["authorization_state"], "allowed")
        self.assertEqual(authorization["authorization_bases"], ["kms_grant"])
        self.assertEqual(authorization["constraint_state"], "encryption_context")
        self.assertEqual(
            authorization["kms_grants"],
            [
                {
                    "source": "aws_kms_grant.orders_runtime",
                    "operation": "kms:Decrypt",
                    "constraints": {"encryption_context_equals": {"service": "orders"}},
                    "constraint_state": "encryption_context",
                    "posture_uncertainties": [],
                    "direct_role_authority": True,
                }
            ],
        )

    def test_source_arn_constrained_grant_is_not_direct_role_authority(self) -> None:
        # SourceArn is in the KMS API but not yet exposed by the Terraform resource schema.
        authorization = _authorization(
            [
                _key(_policy(_admin_key_statement())),
                _role(),
                _grant(constraints=[{"source_arn": (f"arn:aws:ecs:us-east-1:{_ACCOUNT_ID}:service/orders/api")}]),
            ],
            "kms:Decrypt",
        )

        self.assertEqual(authorization["authorization_state"], "unknown")
        self.assertEqual(authorization["authorization_bases"], [])
        self.assertEqual(
            authorization["candidate_authorization_bases"],
            ["kms_grant"],
        )
        self.assertEqual(authorization["constraint_state"], "unknown")
        self.assertFalse(authorization["kms_grants"][0]["direct_role_authority"])
        self.assertEqual(
            authorization["kms_grants"][0]["constraint_state"],
            "service_source_arn",
        )

    def test_conditional_allow_does_not_weaken_independent_grant(self) -> None:
        authorization = _authorization(
            [
                _key(
                    _policy(
                        _admin_key_statement(),
                        _direct_statement(
                            condition={"StringEquals": {"kms:EncryptionContext:service": "orders"}},
                        ),
                    )
                ),
                _role(),
                _grant(),
            ],
            "kms:Decrypt",
        )

        self.assertEqual(authorization["authorization_state"], "allowed")
        self.assertEqual(authorization["authorization_bases"], ["kms_grant"])
        self.assertTrue(authorization["conditional_policy_evidence_present"])
        self.assertFalse(authorization["authorization_requires_condition_evaluation"])
        self.assertFalse(authorization["conditional_evaluation_required"])

    def test_unconditional_iam_deny_wins_over_direct_policy_and_grant(self) -> None:
        authorization = _authorization(
            [
                _key(
                    _policy(
                        _delegation_statement(),
                        _direct_statement(),
                    )
                ),
                _role(
                    _statement("Allow", "kms:Decrypt", _KEY_ARN),
                    _statement("Deny", "kms:Decrypt", _KEY_ARN),
                ),
                _grant(),
            ],
            "kms:Decrypt",
        )

        self.assertEqual(authorization["authorization_state"], "denied")
        self.assertTrue(authorization["explicit_deny"])
        self.assertEqual(authorization["authorization_bases"], [])

    def test_known_iam_deny_remains_effective_when_key_policy_is_unknown(self) -> None:
        authorization = _authorization(
            [
                _key(
                    _policy(_delegation_statement()),
                    unknown_values={"policy": True},
                ),
                _role(_statement("Deny", "kms:Decrypt", _KEY_ARN)),
            ],
            "kms:Decrypt",
        )

        self.assertEqual(authorization["authorization_state"], "denied")
        self.assertTrue(authorization["explicit_deny"])
        self.assertFalse(authorization["key_policy_complete"])

    def test_unconditional_key_policy_deny_wins_over_delegated_iam_allow(self) -> None:
        authorization = _authorization(
            [
                _key(
                    _policy(
                        _delegation_statement(),
                        _direct_statement(effect="Deny"),
                    )
                ),
                _role(_statement("Allow", "kms:Decrypt", _KEY_ARN)),
            ],
            "kms:Decrypt",
        )

        self.assertEqual(authorization["authorization_state"], "denied")
        self.assertTrue(authorization["explicit_deny"])

    def test_conditional_deny_keeps_independent_grant_authority_unknown(self) -> None:
        authorization = _authorization(
            [
                _key(_policy(_admin_key_statement())),
                _role(
                    _statement(
                        "Deny",
                        "kms:Decrypt",
                        _KEY_ARN,
                        condition={"StringNotEquals": {"kms:EncryptionContext:tenant": "orders"}},
                    )
                ),
                _grant(),
            ],
            "kms:Decrypt",
        )

        self.assertEqual(authorization["authorization_state"], "unknown")
        self.assertEqual(authorization["authorization_bases"], [])
        self.assertTrue(authorization["conditional_policy_evidence_present"])
        self.assertTrue(authorization["authorization_requires_condition_evaluation"])
        self.assertTrue(authorization["conditional_evaluation_required"])

    def test_conditional_policy_evidence_remains_unknown(self) -> None:
        authorization = _authorization(
            [
                _key(_policy(_delegation_statement())),
                _role(
                    _statement(
                        "Allow",
                        "kms:Decrypt",
                        _KEY_ARN,
                        condition={"StringEquals": {"kms:EncryptionContext:service": "orders"}},
                    )
                ),
            ],
            "kms:Decrypt",
        )

        self.assertEqual(authorization["authorization_state"], "unknown")
        self.assertTrue(authorization["conditional_policy_evidence_present"])
        self.assertTrue(authorization["authorization_requires_condition_evaluation"])
        self.assertTrue(authorization["conditional_evaluation_required"])
        self.assertEqual(
            authorization["identity_policy_statements"][0]["conditions"],
            [
                {
                    "operator": "StringEquals",
                    "key": "kms:EncryptionContext:service",
                    "values": ["orders"],
                }
            ],
        )

    def test_unknown_or_malformed_key_policy_never_enables_iam_allow(self) -> None:
        malformed_condition_policy = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": {
                    **_delegation_statement(),
                    "Condition": "not-a-condition-map",
                },
            }
        )
        cases = {
            "unknown": _key(
                _policy(_delegation_statement()),
                unknown_values={"policy": True},
            ),
            "malformed_json": _key("{"),
            "malformed_condition": _key(malformed_condition_policy),
        }
        for label, key in cases.items():
            with self.subTest(label=label):
                authorization = _authorization(
                    [
                        key,
                        _role(_statement("Allow", "kms:Decrypt", _KEY_ARN)),
                    ],
                    "kms:Decrypt",
                )
                self.assertEqual(authorization["authorization_state"], "unknown")
                self.assertFalse(authorization["key_policy_complete"])

    def test_competing_key_policy_sources_remain_unknown(self) -> None:
        authorization = _authorization(
            [
                _key(_policy(_delegation_statement())),
                _standalone_key_policy(_policy(_direct_statement())),
                _role(_statement("Allow", "kms:Decrypt", _KEY_ARN)),
            ],
            "kms:Decrypt",
        )

        self.assertEqual(authorization["authorization_state"], "unknown")
        self.assertFalse(authorization["key_policy_complete"])

    def test_unresolved_or_malformed_identity_policy_blocks_direct_authority(self) -> None:
        roles = {
            "attachment": (
                _role(),
                [_unresolved_attachment()],
            ),
            "unknown_inline": (
                _role(
                    _statement("Allow", "kms:Decrypt", _KEY_ARN),
                    unknown_inline_policy=True,
                ),
                [],
            ),
            "malformed_inline": (
                _role(malformed_policy=True),
                [],
            ),
            "malformed_inline_condition": (
                _role(
                    {
                        **_statement("Allow", "kms:Decrypt", _KEY_ARN),
                        "Condition": "not-a-condition-map",
                    }
                ),
                [],
            ),
        }
        for label, (role, extra) in roles.items():
            with self.subTest(label=label):
                authorization = _authorization(
                    [
                        _key(
                            _policy(
                                _admin_key_statement(),
                                _direct_statement(),
                            )
                        ),
                        role,
                        *extra,
                    ],
                    "kms:Decrypt",
                )
                self.assertEqual(authorization["authorization_state"], "unknown")
                self.assertFalse(authorization["identity_policy_complete"])

    def test_on_demand_rotation_preserves_origin_compatibility(
        self,
    ) -> None:
        cases = {
            "aws_kms": (
                "AWS_KMS",
                None,
                "compatible",
            ),
            "external": (
                "EXTERNAL",
                None,
                "compatible",
            ),
            "cloudhsm": (
                "AWS_CLOUDHSM",
                None,
                "incompatible",
            ),
            "external_key_store": (
                "EXTERNAL_KEY_STORE",
                None,
                "incompatible",
            ),
            "unknown": (
                "AWS_KMS",
                {"origin": True},
                "unknown",
            ),
        }

        for label, (origin, unknown_values, expected_state) in cases.items():
            with self.subTest(label=label):
                key = _key(
                    _policy(_direct_statement("kms:RotateKeyOnDemand")),
                    unknown_values=unknown_values,
                )
                key.values["origin"] = origin

                authorization = _authorization(
                    [key, _role()],
                    "kms:RotateKeyOnDemand",
                )

                self.assertEqual(
                    authorization["authorization_state"],
                    "allowed",
                )
                self.assertEqual(
                    authorization["operation_class"],
                    "lifecycle_administration",
                )
                self.assertEqual(
                    authorization["required_key_origins"],
                    ["AWS_KMS", "EXTERNAL"],
                )
                self.assertEqual(
                    authorization["key_origin_compatibility_state"],
                    expected_state,
                )
                self.assertEqual(
                    authorization["key_origin"],
                    None if unknown_values else origin,
                )

    def test_management_operations_preserve_catalog_and_policy_authorization_bases(
        self,
    ) -> None:
        operations = [
            "kms:CreateGrant",
            "kms:PutKeyPolicy",
            "kms:DisableKey",
            "kms:ScheduleKeyDeletion",
            "kms:CancelKeyDeletion",
            "kms:EnableKey",
            "kms:RotateKeyOnDemand",
            "kms:GetKeyPolicy",
        ]
        key = _key(
            _policy(
                _delegation_statement(),
                _direct_statement(operations),
            )
        )
        key.values["origin"] = "AWS_KMS"
        authorizations = {
            authorization["operation"]: authorization
            for authorization in _authorizations(
                key,
                _role(_statement("Allow", operations, _KEY_ARN)),
            )
        }

        self.assertEqual(set(authorizations), set(operations))
        expected_classes = {
            "kms:CreateGrant": "authorization_administration",
            "kms:PutKeyPolicy": "authorization_administration",
            "kms:DisableKey": "disruptive_administration",
            "kms:ScheduleKeyDeletion": "destructive_administration",
            "kms:CancelKeyDeletion": "recovery",
            "kms:EnableKey": "recovery",
            "kms:RotateKeyOnDemand": "lifecycle_administration",
            "kms:GetKeyPolicy": "metadata_read",
        }
        expected_origin_requirements = {
            "kms:RotateKeyOnDemand": (
                ["AWS_KMS", "EXTERNAL"],
                "compatible",
            ),
        }

        for operation, operation_class in expected_classes.items():
            with self.subTest(operation=operation):
                authorization = authorizations[operation]

                self.assertEqual(
                    authorization["authorization_state"],
                    "allowed",
                )
                self.assertEqual(
                    authorization["operation_class"],
                    operation_class,
                )
                self.assertEqual(
                    authorization["authorization_bases"],
                    [
                        "direct_key_policy",
                        "iam_via_account_principal",
                    ],
                )
                self.assertEqual(
                    authorization["key_origin"],
                    "AWS_KMS",
                )

                required_origins, compatibility_state = expected_origin_requirements.get(
                    operation,
                    ([], "not_applicable"),
                )
                self.assertEqual(
                    authorization["required_key_origins"],
                    required_origins,
                )
                self.assertEqual(
                    authorization["key_origin_compatibility_state"],
                    compatibility_state,
                )

        self.assertEqual(
            authorizations["kms:CreateGrant"]["supported_authorization_bases"],
            [
                "direct_key_policy",
                "iam_via_account_principal",
                "kms_grant",
            ],
        )
        self.assertEqual(
            authorizations["kms:PutKeyPolicy"]["supported_authorization_bases"],
            [
                "direct_key_policy",
                "iam_via_account_principal",
            ],
        )

    def test_create_grant_can_be_authorized_by_constrained_kms_grant(
        self,
    ) -> None:
        authorization = _authorization(
            [
                _key(_policy(_admin_key_statement())),
                _role(),
                _grant(
                    operations=["CreateGrant"],
                    constraints=[
                        {
                            "encryption_context_equals": {
                                "service": "orders",
                            }
                        }
                    ],
                ),
            ],
            "kms:CreateGrant",
        )

        self.assertEqual(authorization["authorization_state"], "allowed")
        self.assertEqual(authorization["operation_class"], "authorization_administration")
        self.assertEqual(authorization["authorization_bases"], ["kms_grant"])
        self.assertEqual(
            authorization["supported_authorization_bases"],
            [
                "direct_key_policy",
                "iam_via_account_principal",
                "kms_grant",
            ],
        )
        self.assertEqual(authorization["constraint_state"], "encryption_context")
        self.assertEqual(
            authorization["kms_grants"][0]["constraints"],
            {"encryption_context_equals": {"service": "orders"}},
        )

    def test_management_denies_conditions_and_incomplete_evidence_fail_closed(
        self,
    ) -> None:
        denied = _authorization(
            [
                _key(
                    _policy(
                        _delegation_statement(),
                        _direct_statement("kms:ScheduleKeyDeletion"),
                    )
                ),
                _role(
                    _statement(
                        "Allow",
                        "kms:ScheduleKeyDeletion",
                        _KEY_ARN,
                    ),
                    _statement(
                        "Deny",
                        "kms:ScheduleKeyDeletion",
                        _KEY_ARN,
                    ),
                ),
            ],
            "kms:ScheduleKeyDeletion",
        )
        self.assertEqual(denied["authorization_state"], "denied")
        self.assertTrue(denied["explicit_deny"])

        conditional = _authorization(
            [
                _key(_policy(_delegation_statement("kms:PutKeyPolicy"))),
                _role(
                    _statement(
                        "Allow",
                        "kms:PutKeyPolicy",
                        _KEY_ARN,
                        condition={
                            "StringEquals": {
                                "aws:PrincipalTag/environment": "production",
                            }
                        },
                    )
                ),
            ],
            "kms:PutKeyPolicy",
        )
        self.assertEqual(conditional["authorization_state"], "unknown")
        self.assertTrue(conditional["conditional_policy_evidence_present"])
        self.assertTrue(conditional["authorization_requires_condition_evaluation"])

        incomplete = _authorization(
            [
                _key(
                    _policy(
                        _admin_key_statement(),
                        _direct_statement("kms:DisableKey"),
                    )
                ),
                _role(),
                _unresolved_attachment(),
            ],
            "kms:DisableKey",
        )
        self.assertEqual(incomplete["authorization_state"], "unknown")
        self.assertFalse(incomplete["identity_policy_complete"])
        self.assertEqual(
            incomplete["unresolved_attached_policy_arns"],
            ["arn:aws:iam::aws:policy/ExternalKmsAccess"],
        )

    def test_imported_material_deletion_preserves_origin_compatibility(
        self,
    ) -> None:
        cases = {
            "compatible": ("EXTERNAL", None, "compatible"),
            "incompatible": ("AWS_KMS", None, "incompatible"),
            "unknown": (
                "AWS_KMS",
                {"origin": True},
                "unknown",
            ),
        }
        for label, (origin, unknown_values, expected_state) in cases.items():
            with self.subTest(label=label):
                key = _key(
                    _policy(_direct_statement("kms:DeleteImportedKeyMaterial")),
                    unknown_values=unknown_values,
                )
                key.values["origin"] = origin
                authorization = _authorization(
                    [key, _role()],
                    "kms:DeleteImportedKeyMaterial",
                )

                self.assertEqual(
                    authorization["authorization_state"],
                    "allowed",
                )
                self.assertEqual(
                    authorization["operation_class"],
                    "destructive_administration",
                )
                self.assertEqual(
                    authorization["required_key_origins"],
                    ["EXTERNAL"],
                )
                self.assertEqual(
                    authorization["key_origin_compatibility_state"],
                    expected_state,
                )
                self.assertEqual(
                    authorization["key_origin"],
                    None if unknown_values else origin,
                )

    def test_only_key_arn_resources_match_iam_cryptographic_operations(self) -> None:
        authorizations = _authorizations(
            _key(_policy(_delegation_statement())),
            _role(
                _statement("Allow", "kms:Decrypt", _ALIAS_ARN),
                _statement("Allow", "kms:Sign", _KEY_ID),
                _statement(
                    "Allow",
                    "kms:Encrypt",
                    f"arn:aws:kms:us-east-1:{_ACCOUNT_ID}:key/*",
                ),
                _statement("Allow", "kms:GetPublicKey", "*"),
            ),
        )

        self.assertEqual(
            [authorization["operation"] for authorization in authorizations],
            ["kms:Encrypt", "kms:GetPublicKey"],
        )
        self.assertTrue(all(authorization["authorization_state"] == "allowed" for authorization in authorizations))

    def test_exact_iam_key_arn_does_not_cross_attach_to_another_modeled_key(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _key(_policy(_delegation_statement())),
                _key(
                    _policy(_delegation_statement()),
                    name="other",
                    key_arn=_OTHER_KEY_ARN,
                ),
                _role(_statement("Allow", "kms:Decrypt", _KEY_ARN)),
            ]
        )
        data_key = inventory.get_by_address("aws_kms_key.data")
        other_key = inventory.get_by_address("aws_kms_key.other")
        assert data_key is not None
        assert other_key is not None

        self.assertEqual(
            [authorization["operation"] for authorization in aws_facts(data_key).kms_operation_authorizations],
            ["kms:Decrypt"],
        )
        self.assertEqual(
            aws_facts(other_key).kms_operation_authorizations,
            [],
        )

    def test_source_arn_constrained_service_statement_is_not_role_authority(self) -> None:
        service_statement = _statement(
            "Allow",
            "kms:Decrypt",
            "*",
            principal={"Service": "logs.us-east-1.amazonaws.com"},
            condition={
                "ArnEquals": {"aws:SourceArn": (f"arn:aws:logs:us-east-1:{_ACCOUNT_ID}:log-group:/aws/ecs/orders")}
            },
        )

        self.assertEqual(
            _authorizations(
                _key(_policy(_admin_key_statement(), service_statement)),
                _role(),
            ),
            [],
        )

    def test_cross_account_direct_policy_evidence_remains_unknown(self) -> None:
        authorization = _authorization(
            [
                _key(
                    _policy(
                        _admin_key_statement(),
                        _direct_statement(principal=_FOREIGN_ROLE_ARN),
                    )
                ),
                _role(role_arn=_FOREIGN_ROLE_ARN),
            ],
            "kms:Decrypt",
        )

        self.assertEqual(authorization["authorization_state"], "unknown")
        self.assertFalse(authorization["same_account"])

    def test_unknown_grant_principal_remains_visible_as_uncertainty(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _key(_policy(_admin_key_statement())),
                _role(),
                _grant(unknown_values={"grantee_principal": True}),
            ]
        )
        key = inventory.get_by_address("aws_kms_key.data")
        assert key is not None
        facts = aws_facts(key)

        self.assertEqual(facts.kms_operation_authorizations, [])
        self.assertTrue(
            any(
                "grantee_principal is unknown after planning" in uncertainty
                for uncertainty in facts.kms_operation_authorization_uncertainties
            )
        )

    def test_unknown_grant_operations_remain_visible_as_uncertainty(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _key(_policy(_admin_key_statement())),
                _role(),
                _grant(unknown_values={"operations": True}),
            ]
        )
        key = inventory.get_by_address("aws_kms_key.data")
        assert key is not None
        facts = aws_facts(key)

        self.assertEqual(facts.kms_operation_authorizations, [])
        self.assertTrue(
            any(
                "unresolved KMS grant operations" in uncertainty
                for uncertainty in facts.kms_operation_authorization_uncertainties
            )
        )


if __name__ == "__main__":
    unittest.main()
