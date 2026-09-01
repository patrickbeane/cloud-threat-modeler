from __future__ import annotations

import unittest
from typing import Any

from tests.providers.aws.test_aws_audit_rules import _cloudtrail as aws_cloudtrail
from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _EXECUTION_ROLE_ARN as AWS_EXECUTION_ROLE_ARN,
)
from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _TASK_ROLE_ARN as AWS_TASK_ROLE_ARN,
)
from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _role as aws_role,
)
from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _role_policy_attachment as aws_role_policy_attachment,
)
from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _statement as aws_statement,
)
from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _task_definition as aws_task_definition,
)
from tests.providers.aws.test_aws_public_ecs_dynamodb_mutation_rules import (
    _public_edge as aws_public_edge,
)
from tests.providers.aws.test_aws_public_ecs_dynamodb_mutation_rules import (
    _service as aws_service,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _SYSTEM_PRINCIPAL_ID as AZURE_SYSTEM_PRINCIPAL_ID,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _USER_PRINCIPAL_ID as AZURE_USER_PRINCIPAL_ID,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _resource as azure_resource,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _user_assigned_identity as azure_user_assigned_identity,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _web_app as azure_web_app,
)
from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _PROJECT as GCP_PROJECT,
)
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _SERVICE_ACCOUNT_EMAIL as GCP_SERVICE_ACCOUNT_EMAIL,
)
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _SERVICE_ACCOUNT_MEMBER as GCP_SERVICE_ACCOUNT_MEMBER,
)
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _WORKLOAD_ADDRESS as GCP_WORKLOAD_ADDRESS,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import (
    _public_cloud_run as gcp_public_cloud_run,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import (
    _public_invoker as gcp_public_invoker,
)
from tfstride.models import ResourceInventory, TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.azure.arm_control_plane_authorization import (
    AzureArmControlPlaneAuthorityResult,
    model_arm_control_plane_action_authority,
)
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_decoration.workload_identities import (
    workload_managed_identities,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import (
    AzureDecorationContext,
    AzureResourceIndexBuilder,
)
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.gcp.cloud_run_public_invocation import (
    current_cloud_run_public_invokers,
)
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_decoration.iam import iam_bindings
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_AWS_ACCOUNT_ID = "111122223333"
_AWS_TRAIL_ARN = f"arn:aws:cloudtrail:us-east-1:{_AWS_ACCOUNT_ID}:trail/audit"
_AWS_STOP_LOGGING = "cloudtrail:StopLogging"
_AWS_DELETE_TRAIL = "cloudtrail:DeleteTrail"
_AWS_DELETE_LOG_OBJECT = "s3:DeleteObject"

_GCP_DELETE_SINK = "logging.sinks.delete"
_GCP_DELETE_LOG_ENTRY = "logging.logEntries.delete"
_GCP_CUSTOM_ROLE_NAME = f"projects/{GCP_PROJECT}/roles/auditTelemetryControl"
_GCP_SINK_ADDRESS = "google_logging_project_sink.audit"

_AZURE_WORKLOAD_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Web/sites/orders"
_AZURE_DIAGNOSTIC_ID = f"{_AZURE_WORKLOAD_ID}/providers/Microsoft.Insights/diagnosticSettings/audit"
_AZURE_DIAGNOSTIC_STATE_ID = f"{_AZURE_WORKLOAD_ID}|audit"
_AZURE_DELETE_DIAGNOSTIC = "Microsoft.Insights/DiagnosticSettings/Delete"
_AZURE_DELETE_LOG_BLOB = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"
_AZURE_ROLE_ID = "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/audit-telemetry-control"


def _aws_caller_identity() -> TerraformResource:
    return TerraformResource(
        address="data.aws_caller_identity.current",
        mode="data",
        resource_type="aws_caller_identity",
        name="current",
        provider_name="registry.terraform.io/hashicorp/aws",
        values={
            "account_id": _AWS_ACCOUNT_ID,
            "id": _AWS_ACCOUNT_ID,
            "arn": f"arn:aws:iam::{_AWS_ACCOUNT_ID}:root",
        },
        unknown_values={},
    )


def _aws_trail(
    *,
    enabled: bool = True,
    organization: bool = False,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    trail = aws_cloudtrail(name="audit", unknown_values=unknown_values)
    trail.values["enable_logging"] = enabled
    trail.values["is_organization_trail"] = organization
    return trail


def _aws_resources(
    task_statements: list[dict[str, Any]],
    *,
    execution_statements: list[dict[str, Any]] | None = None,
    public: bool = True,
    trail: TerraformResource | None = None,
    incomplete: bool = False,
) -> list[TerraformResource]:
    resources = [
        _aws_caller_identity(),
        *aws_public_edge(internal=not public),
        trail or _aws_trail(),
        aws_role("orders_task", AWS_TASK_ROLE_ARN, task_statements),
    ]
    if execution_statements is not None:
        resources.append(
            aws_role(
                "orders_execution",
                AWS_EXECUTION_ROLE_ARN,
                execution_statements,
            )
        )
    if incomplete:
        resources.append(
            aws_role_policy_attachment(
                AWS_TASK_ROLE_ARN,
                "arn:aws:iam::aws:policy/AWSCloudTrail_FullAccess",
            )
        )
    resources.extend(
        [
            aws_task_definition(
                execution_role_arn=(AWS_EXECUTION_ROLE_ARN if execution_statements is not None else None)
            ),
            aws_service(),
        ]
    )
    return resources


def _gcp_sink(
    *,
    project: str = GCP_PROJECT,
    destination: object = "storage.googleapis.com/tfstride-audit-logs",
    sink_filter: object = "logName:cloudaudit.googleapis.com",
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return _terraform_resource(
        _GCP_SINK_ADDRESS,
        GcpResourceType.LOGGING_PROJECT_SINK,
        {
            "id": f"projects/{project}/sinks/audit",
            "name": "audit",
            "project": project,
            "destination": destination,
            "filter": sink_filter,
            "writer_identity": ("serviceAccount:cloud-logs@system.gserviceaccount.com"),
        },
        unknown_values=unknown_values,
    )


def _gcp_custom_role(
    permissions: list[str],
    *,
    stage: object = "GA",
    deleted: object = False,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return _terraform_resource(
        "google_project_iam_custom_role.audit_telemetry",
        GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
        {
            "project": GCP_PROJECT,
            "role_id": "auditTelemetryControl",
            "name": _GCP_CUSTOM_ROLE_NAME,
            "permissions": permissions,
            "stage": stage,
            "deleted": deleted,
        },
        unknown_values=unknown_values,
    )


def _gcp_project_member(
    *,
    role: str = _GCP_CUSTOM_ROLE_NAME,
    member: object = GCP_SERVICE_ACCOUNT_MEMBER,
    condition: dict[str, str] | None = None,
    unknown_values: dict[str, object] | None = None,
    name: str = "audit_telemetry",
) -> TerraformResource:
    values: dict[str, object] = {
        "project": GCP_PROJECT,
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


def _gcp_project_binding(
    *,
    role: object = _GCP_CUSTOM_ROLE_NAME,
    members: list[str] | None = None,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return _terraform_resource(
        "google_project_iam_binding.audit_telemetry",
        GcpResourceType.PROJECT_IAM_BINDING,
        {
            "project": GCP_PROJECT,
            "role": role,
            "members": members or ["serviceAccount:other@example.iam.gserviceaccount.com"],
        },
        unknown_values=unknown_values,
    )


def _gcp_workload(*, public: bool = True) -> TerraformResource:
    workload = gcp_public_cloud_run(public_ingress=public)
    if not public:
        workload.values["ingress"] = "INGRESS_TRAFFIC_INTERNAL_ONLY"
    return workload


def _azure_workload(
    *,
    public: bool = True,
    identity_type: str = "SystemAssigned",
    identity_ids: list[str] | None = None,
) -> TerraformResource:
    workload = azure_web_app(
        identity_type=identity_type,
        identity_ids=identity_ids,
    )
    workload.values["public_network_access_enabled"] = public
    return workload


def _azure_diagnostic_setting(
    *,
    target_id: object = _AZURE_WORKLOAD_ID,
    enabled_log: list[dict[str, object]] | None = None,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return azure_resource(
        AzureResourceType.MONITOR_DIAGNOSTIC_SETTING,
        {
            "id": _AZURE_DIAGNOSTIC_STATE_ID,
            "name": "audit",
            "target_resource_id": target_id,
            "log_analytics_workspace_id": (
                "/subscriptions/sub-0001/resourceGroups/obs/providers/Microsoft.OperationalInsights/workspaces/security"
            ),
            "enabled_log": (enabled_log if enabled_log is not None else [{"category_group": "audit"}]),
        },
        name="audit",
        unknown_values=unknown_values,
    )


def _azure_role(
    *,
    actions: list[str],
    not_actions: list[str] | None = None,
    data_actions: list[str] | None = None,
    assignable_scopes: list[str] | None = None,
    unknown_permissions: bool = False,
) -> TerraformResource:
    return azure_resource(
        AzureResourceType.ROLE_DEFINITION,
        {
            "id": _AZURE_ROLE_ID,
            "role_definition_id": _AZURE_ROLE_ID,
            "name": "Audit Telemetry Control",
            "scope": "/subscriptions/sub-0001",
            "assignable_scopes": (assignable_scopes if assignable_scopes is not None else ["/subscriptions/sub-0001"]),
            "permissions": [
                {
                    "actions": actions,
                    "not_actions": not_actions or [],
                    "data_actions": data_actions or [],
                    "not_data_actions": [],
                }
            ],
        },
        name="audit_telemetry",
        unknown_values=({"permissions": [{"actions": True}]} if unknown_permissions else None),
    )


def _azure_assignment(
    *,
    scope: object = _AZURE_DIAGNOSTIC_ID,
    principal_id: object = AZURE_SYSTEM_PRINCIPAL_ID,
    condition: object | None = None,
    unknown_values: dict[str, object] | None = None,
    name: str = "audit_telemetry",
) -> TerraformResource:
    values: dict[str, object] = {
        "scope": scope,
        "role_definition_id": _AZURE_ROLE_ID,
        "principal_id": principal_id,
        "principal_type": "ServicePrincipal",
    }
    if condition is not None:
        values["condition"] = condition
        values["condition_version"] = "2.0"
    return azure_resource(
        AzureResourceType.ROLE_ASSIGNMENT,
        values,
        name=name,
        unknown_values=unknown_values,
    )


def _azure_inventory_and_context(
    resources: list[TerraformResource],
) -> tuple[ResourceInventory, AzureDecorationContext]:
    inventory = AzureNormalizer().normalize(resources)
    return inventory, AzureDecorationContext(index=AzureResourceIndexBuilder().build(list(inventory.resources)))


def _azure_authority(
    inventory: ResourceInventory,
    context: AzureDecorationContext,
    *,
    principal_id: str = AZURE_SYSTEM_PRINCIPAL_ID,
    assignment_address: str = "azurerm_role_assignment.audit_telemetry",
) -> AzureArmControlPlaneAuthorityResult:
    assignment = inventory.get_by_address(assignment_address)
    assert assignment is not None
    return model_arm_control_plane_action_authority(
        assignment,
        context,
        principal_id=principal_id,
        target_arm_id=_AZURE_DIAGNOSTIC_ID,
        requested_actions=(_AZURE_DELETE_DIAGNOSTIC,),
    )


class PublicWorkloadAuditTelemetryDisruptionBoundaryTests(unittest.TestCase):
    """Pin audit-telemetry disruption inputs without constructing new paths."""

    def test_provider_control_operations_remain_distinct_from_historical_log_deletion(
        self,
    ) -> None:
        aws_inventory = AwsNormalizer().normalize(
            _aws_resources(
                [
                    aws_statement(
                        "Allow",
                        [_AWS_STOP_LOGGING, _AWS_DELETE_TRAIL],
                        _AWS_TRAIL_ARN,
                    ),
                    aws_statement(
                        "Allow",
                        _AWS_DELETE_LOG_OBJECT,
                        "arn:aws:s3:::audit-logs/*",
                    ),
                ]
            )
        )
        aws_task_role = aws_inventory.get_by_address("aws_iam_role.orders_task")
        assert aws_task_role is not None
        self.assertEqual(
            [statement.actions for statement in aws_task_role.policy_statements],
            [[_AWS_STOP_LOGGING, _AWS_DELETE_TRAIL], [_AWS_DELETE_LOG_OBJECT]],
        )

        gcp_inventory = GcpNormalizer().normalize(
            [
                _gcp_custom_role([_GCP_DELETE_SINK, _GCP_DELETE_LOG_ENTRY]),
            ]
        )
        gcp_role = gcp_inventory.get_by_address("google_project_iam_custom_role.audit_telemetry")
        assert gcp_role is not None
        self.assertEqual(
            gcp_facts(gcp_role).custom_role_permissions,
            [_GCP_DELETE_SINK, _GCP_DELETE_LOG_ENTRY],
        )

        azure_inventory, azure_context = _azure_inventory_and_context(
            [
                _azure_workload(),
                _azure_diagnostic_setting(),
                _azure_role(
                    actions=[_AZURE_DELETE_DIAGNOSTIC],
                    data_actions=[_AZURE_DELETE_LOG_BLOB],
                ),
                _azure_assignment(),
            ]
        )
        authority = _azure_authority(azure_inventory, azure_context)
        self.assertEqual(authority.state, "granted")
        assert authority.grant is not None
        self.assertEqual(authority.grant["matched_actions"], [_AZURE_DELETE_DIAGNOSTIC])
        self.assertNotIn(
            _AZURE_DELETE_LOG_BLOB,
            authority.grant["matched_actions"],
        )

    def test_aws_exact_task_role_and_active_trail_inputs_are_preserved(self) -> None:
        inventory = AwsNormalizer().normalize(
            _aws_resources(
                [
                    aws_statement(
                        "Allow",
                        [_AWS_STOP_LOGGING, _AWS_DELETE_TRAIL],
                        _AWS_TRAIL_ARN,
                    )
                ]
            )
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        task_role = inventory.get_by_address("aws_iam_role.orders_task")
        trail = inventory.get_by_address("aws_cloudtrail.audit")
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert task_definition is not None
        assert task_role is not None
        assert trail is not None
        assert service is not None

        self.assertEqual(aws_facts(task_definition).task_role_arn, AWS_TASK_ROLE_ARN)
        self.assertIsNone(aws_facts(task_definition).execution_role_arn)
        self.assertEqual(task_role.arn, AWS_TASK_ROLE_ARN)
        self.assertEqual(task_role.policy_statements[0].effect, "Allow")
        self.assertEqual(
            task_role.policy_statements[0].actions,
            [_AWS_STOP_LOGGING, _AWS_DELETE_TRAIL],
        )
        self.assertEqual(task_role.policy_statements[0].resources, [_AWS_TRAIL_ARN])
        self.assertEqual(trail.arn, _AWS_TRAIL_ARN)
        self.assertTrue(aws_facts(trail).cloudtrail_enable_logging)
        self.assertFalse(aws_facts(trail).cloudtrail_organization_trail)
        self.assertEqual(
            aws_facts(service).internet_facing_load_balancer_addresses,
            ["aws_lb.public"],
        )

    def test_aws_execution_role_cannot_substitute_for_runtime_task_role(self) -> None:
        inventory = AwsNormalizer().normalize(
            _aws_resources(
                [],
                execution_statements=[
                    aws_statement(
                        "Allow",
                        [_AWS_STOP_LOGGING, _AWS_DELETE_TRAIL],
                        _AWS_TRAIL_ARN,
                    )
                ],
            )
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        task_role = inventory.get_by_address("aws_iam_role.orders_task")
        execution_role = inventory.get_by_address("aws_iam_role.orders_execution")
        assert task_definition is not None
        assert task_role is not None
        assert execution_role is not None

        facts = aws_facts(task_definition)
        self.assertEqual(facts.task_role_arn, AWS_TASK_ROLE_ARN)
        self.assertEqual(facts.execution_role_arn, AWS_EXECUTION_ROLE_ARN)
        self.assertEqual(task_role.policy_statements, ())
        self.assertEqual(
            execution_role.policy_statements[0].actions,
            [_AWS_STOP_LOGGING, _AWS_DELETE_TRAIL],
        )

    def test_aws_deny_condition_incomplete_and_non_exact_policy_inputs_remain_explicit(
        self,
    ) -> None:
        cases = {
            "explicit deny": _aws_resources(
                [
                    aws_statement("Allow", _AWS_DELETE_TRAIL, _AWS_TRAIL_ARN),
                    aws_statement("Deny", _AWS_DELETE_TRAIL, _AWS_TRAIL_ARN),
                ]
            ),
            "conditional allow": _aws_resources(
                [
                    aws_statement(
                        "Allow",
                        _AWS_DELETE_TRAIL,
                        _AWS_TRAIL_ARN,
                        condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
                    )
                ]
            ),
            "wildcard target": _aws_resources(
                [
                    aws_statement(
                        "Allow",
                        _AWS_DELETE_TRAIL,
                        "arn:aws:cloudtrail:*:*:trail/*",
                    )
                ]
            ),
            "incomplete policy": _aws_resources(
                [aws_statement("Allow", _AWS_DELETE_TRAIL, _AWS_TRAIL_ARN)],
                incomplete=True,
            ),
        }

        for case, resources in cases.items():
            with self.subTest(case=case):
                inventory = AwsNormalizer().normalize(resources)
                role = inventory.get_by_address("aws_iam_role.orders_task")
                assert role is not None
                if case == "explicit deny":
                    self.assertEqual(
                        [statement.effect for statement in role.policy_statements],
                        ["Allow", "Deny"],
                    )
                elif case == "conditional allow":
                    self.assertEqual(len(role.policy_statements[0].conditions), 1)
                elif case == "wildcard target":
                    self.assertNotEqual(
                        role.policy_statements[0].resources,
                        [_AWS_TRAIL_ARN],
                    )
                else:
                    self.assertEqual(
                        aws_facts(role).iam_policy_completeness_state,
                        "unknown",
                    )
                    self.assertTrue(aws_facts(role).iam_policy_posture_uncertainties)

    def test_aws_trail_lifecycle_scope_and_workload_exposure_remain_independent(
        self,
    ) -> None:
        for case, trail, expected_enabled, expected_organization in (
            ("active", _aws_trail(), True, False),
            ("disabled", _aws_trail(enabled=False), False, False),
            ("organization", _aws_trail(organization=True), True, True),
            (
                "unknown",
                _aws_trail(unknown_values={"enable_logging": True}),
                None,
                False,
            ),
        ):
            with self.subTest(case=case):
                inventory = AwsNormalizer().normalize(
                    _aws_resources(
                        [
                            aws_statement(
                                "Allow",
                                _AWS_STOP_LOGGING,
                                _AWS_TRAIL_ARN,
                            )
                        ],
                        trail=trail,
                        public=False,
                    )
                )
                normalized_trail = inventory.get_by_address("aws_cloudtrail.audit")
                service = inventory.get_by_address("aws_ecs_service.orders")
                role = inventory.get_by_address("aws_iam_role.orders_task")
                assert normalized_trail is not None
                assert service is not None
                assert role is not None
                trail_facts = aws_facts(normalized_trail)
                self.assertEqual(
                    trail_facts.cloudtrail_enable_logging,
                    expected_enabled,
                )
                self.assertEqual(
                    trail_facts.cloudtrail_organization_trail,
                    expected_organization,
                )
                self.assertEqual(
                    role.policy_statements[0].actions,
                    [_AWS_STOP_LOGGING],
                )
                self.assertEqual(
                    aws_facts(service).internet_facing_load_balancer_addresses,
                    [],
                )

    def test_gcp_exact_runtime_identity_project_sink_and_public_invoker_are_preserved(
        self,
    ) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _gcp_workload(),
                gcp_public_invoker(),
                _gcp_sink(),
                _gcp_custom_role([_GCP_DELETE_SINK]),
                _gcp_project_member(),
            ]
        )
        workload = inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        sink = inventory.get_by_address(_GCP_SINK_ADDRESS)
        iam = inventory.get_by_address("google_project_iam_member.audit_telemetry")
        role = inventory.get_by_address("google_project_iam_custom_role.audit_telemetry")
        assert workload is not None
        assert sink is not None
        assert iam is not None
        assert role is not None

        self.assertEqual(
            gcp_facts(workload).service_account_email,
            GCP_SERVICE_ACCOUNT_EMAIL,
        )
        self.assertEqual(gcp_facts(sink).project, GCP_PROJECT)
        self.assertEqual(gcp_facts(sink).logging_sink_name, "audit")
        self.assertEqual(
            gcp_facts(sink).logging_sink_destination,
            "storage.googleapis.com/tfstride-audit-logs",
        )
        self.assertIn(
            "cloudaudit.googleapis.com",
            gcp_facts(sink).logging_sink_filter or "",
        )
        self.assertEqual(
            gcp_facts(role).custom_role_permissions,
            [_GCP_DELETE_SINK],
        )
        self.assertEqual(iam_bindings(iam)[0]["members"], [GCP_SERVICE_ACCOUNT_MEMBER])
        self.assertEqual(
            current_cloud_run_public_invokers(workload, list(inventory.resources)),
            [
                {
                    "source": "google_cloud_run_v2_service_iam_member.public_invoker",
                    "role": "roles/run.invoker",
                    "member": "allUsers",
                }
            ],
        )

    def test_gcp_custom_role_lifecycle_and_exact_permissions_remain_distinct(self) -> None:
        cases = (
            ("active", "GA", False, {}, [_GCP_DELETE_SINK]),
            ("disabled", "DISABLED", False, {}, [_GCP_DELETE_SINK]),
            ("deleted", "GA", True, {}, [_GCP_DELETE_SINK]),
            (
                "unknown deletion",
                "GA",
                False,
                {"deleted": True},
                [_GCP_DELETE_SINK],
            ),
            ("wildcard permission", "GA", False, {}, ["logging.sinks.*"]),
        )
        for case, stage, deleted, unknown_values, permissions in cases:
            with self.subTest(case=case):
                inventory = GcpNormalizer().normalize(
                    [
                        _gcp_custom_role(
                            permissions,
                            stage=stage,
                            deleted=deleted,
                            unknown_values=unknown_values,
                        )
                    ]
                )
                role = inventory.get_by_address("google_project_iam_custom_role.audit_telemetry")
                assert role is not None
                facts = gcp_facts(role)
                self.assertEqual(facts.custom_role_stage, stage)
                self.assertEqual(facts.custom_role_permissions, permissions)
                if case == "unknown deletion":
                    self.assertIsNone(facts.custom_role_deleted)
                    self.assertTrue(facts.custom_role_deleted_uncertainties)
                else:
                    self.assertEqual(facts.custom_role_deleted, deleted)

    def test_gcp_conditions_unknown_members_and_iam_manager_overlap_remain_explicit(
        self,
    ) -> None:
        condition = {
            "title": "runtime-window",
            "expression": "request.time < timestamp('2030-01-01T00:00:00Z')",
        }
        inventory = GcpNormalizer().normalize(
            [
                _gcp_project_member(condition=condition),
                _gcp_project_binding(),
                _gcp_project_member(
                    member=None,
                    unknown_values={"member": True},
                    name="audit_telemetry_unknown",
                ),
            ]
        )
        member = inventory.get_by_address("google_project_iam_member.audit_telemetry")
        binding = inventory.get_by_address("google_project_iam_binding.audit_telemetry")
        unknown_member = inventory.get_by_address("google_project_iam_member.audit_telemetry_unknown")
        assert member is not None
        assert binding is not None
        assert unknown_member is not None
        member_binding = iam_bindings(member)[0]
        self.assertEqual(member_binding["condition"], condition)
        self.assertEqual(iam_bindings(binding)[0]["role"], _GCP_CUSTOM_ROLE_NAME)
        self.assertNotIn(
            GCP_SERVICE_ACCOUNT_MEMBER,
            iam_bindings(binding)[0]["members"],
        )
        self.assertEqual(
            iam_bindings(unknown_member)[0]["members_state"],
            "unknown",
        )

    def test_gcp_sink_scope_relevance_uncertainty_and_private_exposure_are_separate(
        self,
    ) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _gcp_workload(public=False),
                _gcp_sink(
                    destination=None,
                    sink_filter="severity>=ERROR",
                    unknown_values={"destination": True},
                ),
                _gcp_custom_role([_GCP_DELETE_SINK]),
                _gcp_project_member(),
            ]
        )
        workload = inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        sink = inventory.get_by_address(_GCP_SINK_ADDRESS)
        iam = inventory.get_by_address("google_project_iam_member.audit_telemetry")
        assert workload is not None
        assert sink is not None
        assert iam is not None

        self.assertEqual(
            gcp_facts(workload).serverless_ingress,
            "INGRESS_TRAFFIC_INTERNAL_ONLY",
        )
        self.assertEqual(
            gcp_facts(workload).service_account_email,
            GCP_SERVICE_ACCOUNT_EMAIL,
        )
        self.assertEqual(gcp_facts(sink).logging_sink_scope_type, "project")
        self.assertEqual(gcp_facts(sink).logging_sink_scope, GCP_PROJECT)
        self.assertIsNone(gcp_facts(sink).logging_sink_destination)
        self.assertEqual(gcp_facts(sink).logging_sink_filter, "severity>=ERROR")
        self.assertTrue(gcp_facts(sink).audit_security_posture_uncertainties)
        self.assertEqual(iam_bindings(iam)[0]["members"], [GCP_SERVICE_ACCOUNT_MEMBER])

    def test_gcp_organization_sink_is_not_flattened_into_project_scope(self) -> None:
        organization_sink = _terraform_resource(
            "google_logging_organization_sink.audit",
            GcpResourceType.LOGGING_ORGANIZATION_SINK,
            {
                "id": "organizations/1234567890/sinks/audit",
                "name": "audit",
                "org_id": "1234567890",
                "destination": "storage.googleapis.com/tfstride-audit-logs",
                "filter": "logName:cloudaudit.googleapis.com",
                "include_children": True,
            },
        )
        inventory = GcpNormalizer().normalize([_gcp_sink(), organization_sink])
        project_sink = inventory.get_by_address(_GCP_SINK_ADDRESS)
        org_sink = inventory.get_by_address("google_logging_organization_sink.audit")
        assert project_sink is not None
        assert org_sink is not None
        self.assertEqual(gcp_facts(project_sink).logging_sink_scope_type, "project")
        self.assertEqual(gcp_facts(project_sink).logging_sink_scope, GCP_PROJECT)
        self.assertEqual(gcp_facts(org_sink).logging_sink_scope_type, "organization")
        self.assertEqual(gcp_facts(org_sink).logging_sink_scope, "1234567890")
        self.assertTrue(gcp_facts(org_sink).logging_sink_include_children)

    def test_azure_exact_runtime_identity_diagnostic_target_and_action_are_preserved(
        self,
    ) -> None:
        inventory, context = _azure_inventory_and_context(
            [
                _azure_workload(),
                _azure_diagnostic_setting(),
                _azure_role(actions=[_AZURE_DELETE_DIAGNOSTIC]),
                _azure_assignment(),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        diagnostic = inventory.get_by_address("azurerm_monitor_diagnostic_setting.audit")
        assert workload is not None
        assert diagnostic is not None
        identities, uncertainties = workload_managed_identities(workload, context)
        self.assertEqual(uncertainties, [])
        self.assertEqual(
            [(identity.address, kind, azure_facts(identity).principal_id) for identity, kind in identities],
            [
                (
                    "azurerm_linux_web_app.orders",
                    "system_assigned",
                    AZURE_SYSTEM_PRINCIPAL_ID,
                )
            ],
        )
        diagnostic_facts = azure_facts(diagnostic)
        self.assertEqual(diagnostic_facts.diagnostic_setting_id, _AZURE_DIAGNOSTIC_STATE_ID)
        self.assertEqual(
            diagnostic_facts.diagnostic_target_resource_id,
            _AZURE_WORKLOAD_ID,
        )
        self.assertEqual(
            diagnostic_facts.diagnostic_enabled_log_category_groups,
            ["audit"],
        )
        authority = _azure_authority(inventory, context)
        self.assertEqual(authority.state, "granted")
        assert authority.grant is not None
        self.assertEqual(authority.grant["target_arm_id"], _AZURE_DIAGNOSTIC_ID)
        self.assertEqual(authority.grant["matched_actions"], [_AZURE_DELETE_DIAGNOSTIC])

    def test_azure_data_actions_conditions_exclusions_and_assignable_scope_fail_closed(
        self,
    ) -> None:
        cases = {
            "data action only": (
                _azure_role(actions=[], data_actions=[_AZURE_DELETE_DIAGNOSTIC]),
                _azure_assignment(),
                "not_granted",
            ),
            "not action": (
                _azure_role(
                    actions=["Microsoft.Insights/DiagnosticSettings/*"],
                    not_actions=[_AZURE_DELETE_DIAGNOSTIC],
                ),
                _azure_assignment(),
                "not_granted",
            ),
            "condition": (
                _azure_role(actions=[_AZURE_DELETE_DIAGNOSTIC]),
                _azure_assignment(
                    condition=("@Resource[Microsoft.Insights/DiagnosticSettings:Name] StringEquals 'audit'")
                ),
                "unknown",
            ),
            "unknown condition version": (
                _azure_role(actions=[_AZURE_DELETE_DIAGNOSTIC]),
                _azure_assignment(unknown_values={"condition_version": True}),
                "unknown",
            ),
            "outside assignable scope": (
                _azure_role(
                    actions=[_AZURE_DELETE_DIAGNOSTIC],
                    assignable_scopes=["/subscriptions/other-subscription"],
                ),
                _azure_assignment(),
                "unknown",
            ),
            "unknown actions": (
                _azure_role(
                    actions=[_AZURE_DELETE_DIAGNOSTIC],
                    unknown_permissions=True,
                ),
                _azure_assignment(),
                "unknown",
            ),
            "other identity": (
                _azure_role(actions=[_AZURE_DELETE_DIAGNOSTIC]),
                _azure_assignment(principal_id="other-principal"),
                "unrelated",
            ),
        }
        for case, (role, assignment, expected_state) in cases.items():
            with self.subTest(case=case):
                inventory, context = _azure_inventory_and_context(
                    [
                        _azure_workload(),
                        _azure_diagnostic_setting(),
                        role,
                        assignment,
                    ]
                )
                self.assertEqual(
                    _azure_authority(inventory, context).state,
                    expected_state,
                )

    def test_azure_attached_user_identity_and_system_identity_remain_distinct(self) -> None:
        workload = _azure_workload(
            identity_type="SystemAssigned, UserAssigned",
            identity_ids=["azurerm_user_assigned_identity.orders_runtime.id"],
        )
        inventory, context = _azure_inventory_and_context(
            [
                workload,
                azure_user_assigned_identity(),
                _azure_diagnostic_setting(),
                _azure_role(actions=[_AZURE_DELETE_DIAGNOSTIC]),
                _azure_assignment(),
                _azure_assignment(
                    principal_id=AZURE_USER_PRINCIPAL_ID,
                    name="audit_telemetry_user",
                ),
            ]
        )
        normalized_workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert normalized_workload is not None
        identities, uncertainties = workload_managed_identities(
            normalized_workload,
            context,
        )
        self.assertEqual(uncertainties, [])
        self.assertEqual(
            sorted(
                (
                    identity.address,
                    kind,
                    azure_facts(identity).principal_id,
                )
                for identity, kind in identities
            ),
            [
                (
                    "azurerm_linux_web_app.orders",
                    "system_assigned",
                    AZURE_SYSTEM_PRINCIPAL_ID,
                ),
                (
                    "azurerm_user_assigned_identity.orders_runtime",
                    "user_assigned",
                    AZURE_USER_PRINCIPAL_ID,
                ),
            ],
        )
        self.assertEqual(
            _azure_authority(inventory, context).state,
            "granted",
        )
        self.assertEqual(
            _azure_authority(
                inventory,
                context,
                principal_id=AZURE_USER_PRINCIPAL_ID,
                assignment_address="azurerm_role_assignment.audit_telemetry_user",
            ).state,
            "granted",
        )

    def test_azure_diagnostic_relevance_destination_uncertainty_and_private_exposure_are_separate(
        self,
    ) -> None:
        diagnostic = _azure_diagnostic_setting(
            enabled_log=[{"category": "AppServiceHTTPLogs"}],
            unknown_values={"log_analytics_workspace_id": True},
        )
        inventory, context = _azure_inventory_and_context(
            [
                _azure_workload(public=False),
                diagnostic,
                _azure_role(actions=[_AZURE_DELETE_DIAGNOSTIC]),
                _azure_assignment(),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        normalized_diagnostic = inventory.get_by_address("azurerm_monitor_diagnostic_setting.audit")
        assert workload is not None
        assert normalized_diagnostic is not None
        diagnostic_facts = azure_facts(normalized_diagnostic)
        self.assertFalse(azure_facts(workload).public_network_access_enabled)
        self.assertEqual(
            diagnostic_facts.diagnostic_enabled_log_categories,
            ["AppServiceHTTPLogs"],
        )
        self.assertEqual(
            diagnostic_facts.diagnostic_enabled_log_category_groups,
            [],
        )
        self.assertIsNone(diagnostic_facts.diagnostic_log_analytics_workspace_id)
        self.assertTrue(azure_facts(normalized_diagnostic).azure_security_posture_uncertainties)
        self.assertEqual(_azure_authority(inventory, context).state, "granted")


if __name__ == "__main__":
    unittest.main()
