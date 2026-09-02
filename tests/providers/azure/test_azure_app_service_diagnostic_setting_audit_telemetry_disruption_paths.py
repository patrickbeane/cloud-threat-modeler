from __future__ import annotations

import unittest

from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _SYSTEM_PRINCIPAL_ID,
    _USER_PRINCIPAL_ID,
    _resource,
    _symbolic_resolution,
    _user_assigned_identity,
    _web_app,
)
from tests.providers.test_public_workload_audit_telemetry_disruption_boundaries import (
    _AZURE_DELETE_DIAGNOSTIC,
    _AZURE_DIAGNOSTIC_ID,
    _AZURE_DIAGNOSTIC_STATE_ID,
    _AZURE_WORKLOAD_ID,
    _azure_assignment,
    _azure_diagnostic_setting,
    _azure_role,
    _azure_workload,
)
from tests.providers.test_public_workload_structured_data_topology_destruction_boundaries import (
    _azure_management_lock,
)
from tfstride.models import NormalizedResource, ResourceInventory, TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_decoration.app_service_diagnostic_setting_audit_telemetry_disruption_paths import (
    current_app_service_diagnostic_setting_audit_telemetry_disruption_paths,
)
from tfstride.providers.azure.resource_decoration_stages import default_azure_decoration_stages
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext, AzureResourceIndexBuilder
from tfstride.providers.azure.resource_types import AzureResourceType

_LOG_ANALYTICS_ID = (
    "/subscriptions/sub-0001/resourceGroups/obs/providers/Microsoft.OperationalInsights/workspaces/security"
)
_STORAGE_ID = "/subscriptions/sub-0001/resourceGroups/obs/providers/Microsoft.Storage/storageAccounts/auditlogs"
_EVENTHUB_RULE_ID = (
    "/subscriptions/sub-0001/resourceGroups/obs/providers/Microsoft.EventHub/namespaces/audit/authorizationRules/export"
)
_MARKETPLACE_ID = "/subscriptions/sub-0001/resourceGroups/obs/providers/Microsoft.Datadog/monitors/security"
_ARBITRARY_MONITORED_RESOURCE_ID = (
    "/subscriptions/sub-0001/resourceGroups/ops/providers/Microsoft.Storage/storageAccounts/operations"
)
_ARBITRARY_DIAGNOSTIC_ID = f"{_ARBITRARY_MONITORED_RESOURCE_ID}/providers/Microsoft.Insights/diagnosticSettings/audit"
_ARBITRARY_DIAGNOSTIC_STATE_ID = f"{_ARBITRARY_MONITORED_RESOURCE_ID}|audit"
_OWNER_ROLE_DEFINITION_ID = (
    "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
)
_MONITORING_CONTRIBUTOR_ROLE_DEFINITION_ID = (
    "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/749f88d5-cbae-40b8-bcfc-e573ddc772fa"
)


def _valid_resources(
    *,
    workload: TerraformResource | None = None,
    diagnostic: TerraformResource | None = None,
    role: TerraformResource | None = None,
    assignment: TerraformResource | None = None,
) -> list[TerraformResource]:
    return [
        workload or _azure_workload(),
        diagnostic or _azure_diagnostic_setting(),
        role or _azure_role(actions=[_AZURE_DELETE_DIAGNOSTIC]),
        assignment or _azure_assignment(),
    ]


def _normalize(
    resources: list[TerraformResource],
) -> tuple[ResourceInventory, AzureDecorationContext]:
    inventory = AzureNormalizer().normalize(resources)
    context = AzureDecorationContext(index=AzureResourceIndexBuilder().build(list(inventory.resources)))
    return inventory, context


def _workload_paths(resources: list[TerraformResource]):
    inventory, _context = _normalize(resources)
    workload = inventory.get_by_address("azurerm_linux_web_app.orders")
    assert workload is not None
    return azure_facts(workload).app_service_diagnostic_setting_audit_telemetry_disruption_paths


def _symbolic_diagnostic_assignment() -> TerraformResource:
    return _resource(
        AzureResourceType.ROLE_ASSIGNMENT,
        {
            "scope": None,
            "role_definition_id": (
                "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/audit-telemetry-control"
            ),
            "principal_id": _SYSTEM_PRINCIPAL_ID,
            "principal_type": "ServicePrincipal",
        },
        name="symbolic_diagnostic",
        unknown_values={"scope": True},
        reference_resolutions=(
            _symbolic_resolution(
                ("scope",),
                "azurerm_monitor_diagnostic_setting.audit.id",
            ),
        ),
    )


def _built_in_assignment(
    *,
    scope: str = _AZURE_WORKLOAD_ID,
    principal_id: str = _SYSTEM_PRINCIPAL_ID,
    role_definition_name: str | None = "Owner",
    role_definition_id: str | None = _OWNER_ROLE_DEFINITION_ID,
) -> TerraformResource:
    values: dict[str, object] = {
        "scope": scope,
        "principal_id": principal_id,
        "principal_type": "ServicePrincipal",
    }
    if role_definition_name is not None:
        values["role_definition_name"] = role_definition_name
    if role_definition_id is not None:
        values["role_definition_id"] = role_definition_id
    return _resource(
        AzureResourceType.ROLE_ASSIGNMENT,
        values,
        name="diagnostic_owner",
    )


class AzureAppServiceDiagnosticSettingAuditTelemetryDisruptionPathTests(unittest.TestCase):
    def test_exact_system_identity_setting_and_actions_allow_produce_one_path(self) -> None:
        paths = _workload_paths(_valid_resources())

        self.assertEqual(len(paths), 1)
        path = paths[0]
        self.assertEqual(path["workload_address"], "azurerm_linux_web_app.orders")
        self.assertEqual(path["identity_address"], "azurerm_linux_web_app.orders")
        self.assertEqual(path["identity_kind"], "system_assigned")
        self.assertEqual(path["principal_id"], _SYSTEM_PRINCIPAL_ID)
        self.assertEqual(path["diagnostic_setting_address"], "azurerm_monitor_diagnostic_setting.audit")
        self.assertEqual(path["diagnostic_setting_id"], _AZURE_DIAGNOSTIC_STATE_ID)
        self.assertEqual(path["diagnostic_setting_arm_id"], _AZURE_DIAGNOSTIC_ID)
        self.assertEqual(path["diagnostic_setting_reference"], _AZURE_DIAGNOSTIC_STATE_ID)
        self.assertEqual(path["monitored_resource_address"], "azurerm_linux_web_app.orders")
        self.assertEqual(path["monitored_resource_id"], _AZURE_WORKLOAD_ID)
        self.assertEqual(
            path["target_model_evidence_addresses"],
            ["azurerm_linux_web_app.orders", "azurerm_monitor_diagnostic_setting.audit"],
        )
        self.assertEqual(path["operation"], _AZURE_DELETE_DIAGNOSTIC)
        self.assertEqual(path["authorization_grant"]["matched_actions"], [_AZURE_DELETE_DIAGNOSTIC])
        self.assertEqual(path["authorization_grant"]["role_evidence"]["role_kind"], "custom")
        self.assertEqual(
            path["authorization_grant"]["diagnostic_settings_data_actions_authorization_effect"],
            "not_used_for_arm_diagnostic_setting_deletion",
        )
        self.assertEqual(path["destination_evidence"]["destination_basis"], "log_analytics_workspace")
        self.assertEqual(path["destination_evidence"]["log_analytics_workspace_id"], _LOG_ANALYTICS_ID)
        self.assertEqual(
            path["audit_telemetry_relevance_evidence"]["matched_audit_security_category_group"],
            "audit",
        )
        self.assertEqual(path["management_lock_evidence"]["modeled_management_lock_state"], "not_observed")
        self.assertFalse(path["outcome_evidence"]["successful_operation_observed"])
        self.assertFalse(path["outcome_evidence"]["historical_log_deletion_authorized_by_operation"])
        self.assertFalse(path["outcome_evidence"]["historical_log_deletion_observed"])
        self.assertFalse(path["outcome_evidence"]["destination_resource_deletion_authorized_by_operation"])
        self.assertFalse(path["outcome_evidence"]["destination_resource_deletion_observed"])
        self.assertFalse(path["outcome_evidence"]["all_resource_diagnostic_settings_evaluated"])
        self.assertFalse(path["outcome_evidence"]["out_of_plan_diagnostic_settings_evaluated"])
        self.assertFalse(path["outcome_evidence"]["restoration_observed"])

    def test_private_workload_retains_the_modeled_authority_path(self) -> None:
        paths = _workload_paths(_valid_resources(workload=_azure_workload(public=False)))

        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["credential_context"], "workload_runtime")

    def test_built_in_parent_scope_is_applicable_to_exact_extension_target(self) -> None:
        paths = _workload_paths(
            [
                _azure_workload(),
                _azure_diagnostic_setting(),
                _built_in_assignment(),
            ]
        )

        self.assertEqual(len(paths), 1)
        grant = paths[0]["authorization_grant"]
        self.assertEqual(grant["assignment_scope_arm_id"], _AZURE_WORKLOAD_ID)
        self.assertEqual(grant["target_arm_id"], _AZURE_DIAGNOSTIC_ID)
        self.assertEqual(grant["role_evidence"]["role_kind"], "built_in")

    def test_monitoring_contributor_grants_diagnostic_setting_delete(self) -> None:
        assignments = {
            "role id": _built_in_assignment(
                role_definition_name=None,
                role_definition_id=_MONITORING_CONTRIBUTOR_ROLE_DEFINITION_ID,
            ),
            "role name": _built_in_assignment(
                role_definition_name="Monitoring Contributor",
                role_definition_id=None,
            ),
        }
        for case, assignment in assignments.items():
            with self.subTest(case=case):
                paths = _workload_paths(
                    [
                        _azure_workload(),
                        _azure_diagnostic_setting(),
                        assignment,
                    ]
                )

                self.assertEqual(len(paths), 1)
                grant = paths[0]["authorization_grant"]
                self.assertEqual(
                    grant["matched_actions"],
                    [_AZURE_DELETE_DIAGNOSTIC],
                )
                self.assertEqual(
                    grant["role_actions"],
                    ["Microsoft.Insights/DiagnosticSettings/*"],
                )
                self.assertEqual(
                    grant["role_evidence"]["role_kind"],
                    "built_in",
                )

    def test_attached_user_assigned_identity_correlates_exact_principal(self) -> None:
        workload = _azure_workload(
            identity_type="UserAssigned",
            identity_ids=["azurerm_user_assigned_identity.orders_runtime.id"],
        )
        paths = _workload_paths(
            [
                workload,
                _user_assigned_identity(),
                _azure_diagnostic_setting(),
                _azure_role(actions=[_AZURE_DELETE_DIAGNOSTIC]),
                _azure_assignment(principal_id=_USER_PRINCIPAL_ID),
            ]
        )

        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["identity_address"], "azurerm_user_assigned_identity.orders_runtime")
        self.assertEqual(paths[0]["identity_kind"], "user_assigned")
        self.assertEqual(paths[0]["principal_id"], _USER_PRINCIPAL_ID)

    def test_stale_unattached_or_wrong_runtime_identity_does_not_produce_a_path(self) -> None:
        cases = {
            "system principal unresolved": _web_app(principal_id=None),
            "identity not attached": _web_app(identity_type="None"),
            "wrong current system principal": _web_app(principal_id="replacement-principal"),
        }
        for case, workload in cases.items():
            with self.subTest(case=case):
                self.assertEqual(_workload_paths(_valid_resources(workload=workload)), [])

        unattached_user = _azure_workload(identity_type="UserAssigned", identity_ids=["missing.identity.id"])
        self.assertEqual(
            _workload_paths(
                _valid_resources(
                    workload=unattached_user,
                    assignment=_azure_assignment(principal_id=_USER_PRINCIPAL_ID),
                )
            ),
            [],
        )

    def test_exact_parent_subscription_setting_and_assignment_targets_must_correlate(self) -> None:
        wrong_parent = _azure_diagnostic_setting(
            target_id=("/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Web/sites/other")
        )
        wrong_subscription = _azure_diagnostic_setting()
        wrong_subscription.values["id"] = _AZURE_DIAGNOSTIC_STATE_ID.replace("sub-0001", "sub-0002")
        wrong_setting_name = _azure_diagnostic_setting()
        wrong_setting_name.values["id"] = f"{_AZURE_WORKLOAD_ID}|other"
        wrong_assignment_target = _azure_assignment(
            scope=(
                "/subscriptions/sub-0001/resourceGroups/app/providers/"
                "Microsoft.Web/sites/other/providers/Microsoft.Insights/diagnosticSettings/audit"
            )
        )

        cases = {
            "wrong parent": _valid_resources(diagnostic=wrong_parent),
            "provider composite ID has wrong parent": _valid_resources(diagnostic=wrong_subscription),
            "provider composite ID has wrong setting name": _valid_resources(diagnostic=wrong_setting_name),
            "wrong assignment target": _valid_resources(assignment=wrong_assignment_target),
        }
        for case, resources in cases.items():
            with self.subTest(case=case):
                self.assertEqual(_workload_paths(resources), [])

    def test_missing_computed_id_is_derived_only_from_exact_parent_and_name(self) -> None:
        diagnostic = _azure_diagnostic_setting()
        diagnostic.values.pop("id")

        paths = _workload_paths(_valid_resources(diagnostic=diagnostic))

        self.assertEqual(len(paths), 1)
        self.assertIsNone(paths[0]["diagnostic_setting_id"])
        self.assertEqual(paths[0]["diagnostic_setting_arm_id"], _AZURE_DIAGNOSTIC_ID)

    def test_unknown_computed_id_is_derived_only_from_exact_parent_and_name(self) -> None:
        diagnostic = _azure_diagnostic_setting()
        diagnostic.unknown_values["id"] = True

        paths = _workload_paths(_valid_resources(diagnostic=diagnostic))

        self.assertEqual(len(paths), 1)
        self.assertIsNone(paths[0]["diagnostic_setting_id"])
        self.assertEqual(paths[0]["diagnostic_setting_arm_id"], _AZURE_DIAGNOSTIC_ID)

    def test_unresolved_symbolic_setting_id_is_not_fabricated_as_arm_scope(self) -> None:
        diagnostic = _azure_diagnostic_setting()
        diagnostic.unknown_values["id"] = True

        paths = _workload_paths(
            _valid_resources(
                diagnostic=diagnostic,
                assignment=_symbolic_diagnostic_assignment(),
            )
        )

        self.assertEqual(paths, [])

    def test_provider_composite_id_is_not_accepted_as_arm_assignment_scope(self) -> None:
        paths = _workload_paths(
            _valid_resources(
                assignment=_azure_assignment(scope=_AZURE_DIAGNOSTIC_STATE_ID),
            )
        )

        self.assertEqual(paths, [])

    def test_legacy_service_setting_name_fails_closed(self) -> None:
        diagnostic = _azure_diagnostic_setting()
        diagnostic.values["name"] = "service"
        diagnostic.values["id"] = f"{_AZURE_WORKLOAD_ID}|service"
        service_arm_id = f"{_AZURE_WORKLOAD_ID}/providers/Microsoft.Insights/diagnosticSettings/service"

        paths = _workload_paths(
            _valid_resources(
                diagnostic=diagnostic,
                assignment=_azure_assignment(scope=service_arm_id),
            )
        )

        self.assertEqual(paths, [])

    def test_control_plane_authorization_fail_closed_cases(self) -> None:
        cases = {
            "data actions only": _valid_resources(
                role=_azure_role(actions=[], data_actions=[_AZURE_DELETE_DIAGNOSTIC])
            ),
            "not actions exclusion": _valid_resources(
                role=_azure_role(
                    actions=["Microsoft.Insights/DiagnosticSettings/*"],
                    not_actions=[_AZURE_DELETE_DIAGNOSTIC],
                )
            ),
            "assignment condition": _valid_resources(
                assignment=_azure_assignment(
                    condition=("@Resource[Microsoft.Insights/DiagnosticSettings:Name] StringEquals 'audit'")
                )
            ),
            "unknown assignment scope": _valid_resources(assignment=_azure_assignment(unknown_values={"scope": True})),
            "unknown role actions": _valid_resources(
                role=_azure_role(actions=[_AZURE_DELETE_DIAGNOSTIC], unknown_permissions=True)
            ),
            "incompatible assignment scope": _valid_resources(
                assignment=_azure_assignment(scope="/subscriptions/other-subscription")
            ),
            "incompatible custom assignable scope": _valid_resources(
                role=_azure_role(
                    actions=[_AZURE_DELETE_DIAGNOSTIC],
                    assignable_scopes=["/subscriptions/other-subscription"],
                )
            ),
            "ambiguous principal": _valid_resources(
                assignment=_azure_assignment(
                    principal_id=None,
                    unknown_values={"principal_id": True},
                )
            ),
        }
        for case, resources in cases.items():
            with self.subTest(case=case):
                self.assertEqual(_workload_paths(resources), [])

        self.assertEqual(
            _workload_paths(
                [
                    _azure_workload(),
                    _azure_diagnostic_setting(),
                    _azure_assignment(),
                ]
            ),
            [],
        )

    def test_unknown_candidate_assignment_suppresses_otherwise_valid_allow(self) -> None:
        unresolved = _azure_assignment(
            unknown_values={"condition_version": True},
            name="unresolved",
        )
        self.assertEqual(
            _workload_paths([*_valid_resources(), unresolved]),
            [],
        )

    def test_audit_relevance_requires_resolved_enabled_category_or_group(self) -> None:
        audit_category = _azure_diagnostic_setting(enabled_log=[{"category": "AppServiceAuditLogs"}])
        audit_group = _azure_diagnostic_setting(enabled_log=[{"category_group": "audit"}])
        app_service_all_logs = _azure_diagnostic_setting(enabled_log=[{"category_group": "allLogs"}])
        irrelevant = _azure_diagnostic_setting(enabled_log=[{"category": "AppServiceHTTPLogs"}])
        unresolved = _azure_diagnostic_setting(
            enabled_log=[{"category_group": "audit"}],
            unknown_values={"enabled_log": [{"category_group": True}]},
        )

        for case, diagnostic, expected_basis in (
            ("explicit AppServiceAuditLogs", audit_category, "audit_security_category"),
            ("audit category group", audit_group, "audit_security_category_group"),
            ("App Service allLogs", app_service_all_logs, "audit_security_category_group"),
        ):
            with self.subTest(case=case):
                paths = _workload_paths(_valid_resources(diagnostic=diagnostic))
                self.assertEqual(len(paths), 1)
                self.assertEqual(
                    paths[0]["audit_telemetry_relevance_evidence"]["relevance_basis"],
                    expected_basis,
                )

        self.assertEqual(_workload_paths(_valid_resources(diagnostic=irrelevant)), [])
        self.assertEqual(_workload_paths(_valid_resources(diagnostic=unresolved)), [])

    def test_all_logs_does_not_establish_relevance_for_arbitrary_monitored_resource(self) -> None:
        monitored_resource = _resource(
            AzureResourceType.STORAGE_ACCOUNT,
            {
                "id": _ARBITRARY_MONITORED_RESOURCE_ID,
                "name": "operations",
            },
            name="operations",
        )
        diagnostic = _azure_diagnostic_setting(
            target_id=_ARBITRARY_MONITORED_RESOURCE_ID,
            enabled_log=[{"category_group": "allLogs"}],
        )
        diagnostic.values["id"] = _ARBITRARY_DIAGNOSTIC_STATE_ID

        paths = _workload_paths(
            [
                *_valid_resources(
                    diagnostic=diagnostic,
                    assignment=_azure_assignment(scope=_ARBITRARY_DIAGNOSTIC_ID),
                ),
                monitored_resource,
            ]
        )

        audit_diagnostic = _azure_diagnostic_setting(
            target_id=_ARBITRARY_MONITORED_RESOURCE_ID,
            enabled_log=[{"category_group": "audit"}],
        )
        audit_diagnostic.values["id"] = _ARBITRARY_DIAGNOSTIC_STATE_ID
        audit_paths = _workload_paths(
            [
                *_valid_resources(
                    diagnostic=audit_diagnostic,
                    assignment=_azure_assignment(scope=_ARBITRARY_DIAGNOSTIC_ID),
                ),
                monitored_resource,
            ]
        )

        self.assertEqual(paths, [])
        self.assertEqual(len(audit_paths), 1)

    def test_each_modeled_destination_can_establish_current_delivery(self) -> None:
        cases = {
            "log_analytics_workspace_id": ("log_analytics_workspace", _LOG_ANALYTICS_ID),
            "storage_account_id": ("storage_account", _STORAGE_ID),
            "eventhub_authorization_rule_id": ("event_hub", _EVENTHUB_RULE_ID),
            "partner_solution_id": ("marketplace_partner", _MARKETPLACE_ID),
        }
        for field, (basis, value) in cases.items():
            with self.subTest(field=field):
                diagnostic = _azure_diagnostic_setting()
                diagnostic.values.pop("log_analytics_workspace_id")
                diagnostic.values[field] = value
                if field == "eventhub_authorization_rule_id":
                    diagnostic.values["eventhub_name"] = "security"
                paths = _workload_paths(_valid_resources(diagnostic=diagnostic))
                self.assertEqual(len(paths), 1)
                self.assertEqual(paths[0]["destination_evidence"]["destination_basis"], basis)

    def test_missing_or_unresolved_destination_fails_closed(self) -> None:
        missing = _azure_diagnostic_setting()
        missing.values.pop("log_analytics_workspace_id")
        unresolved = _azure_diagnostic_setting(unknown_values={"log_analytics_workspace_id": True})
        eventhub_name_only = _azure_diagnostic_setting()
        eventhub_name_only.values.pop("log_analytics_workspace_id")
        eventhub_name_only.values["eventhub_name"] = "security"

        for case, diagnostic in {
            "missing": missing,
            "unresolved": unresolved,
            "event hub name only": eventhub_name_only,
        }.items():
            with self.subTest(case=case):
                self.assertEqual(_workload_paths(_valid_resources(diagnostic=diagnostic)), [])

    def test_blocking_and_unresolved_management_locks_fail_closed(self) -> None:
        cases = {
            "cannot delete exact setting": _azure_management_lock(scope=_AZURE_DIAGNOSTIC_ID),
            "read only parent": _azure_management_lock(
                scope=_AZURE_WORKLOAD_ID,
                level="ReadOnly",
            ),
            "unknown scope": _azure_management_lock(
                scope=_AZURE_WORKLOAD_ID,
                unknown_scope=True,
            ),
            "unknown applicable level": _azure_management_lock(
                scope=_AZURE_DIAGNOSTIC_ID,
                unknown_level=True,
            ),
        }
        for case, lock in cases.items():
            with self.subTest(case=case):
                self.assertEqual(_workload_paths([*_valid_resources(), lock]), [])

        unrelated = _azure_management_lock(
            scope=("/subscriptions/sub-0001/resourceGroups/other/providers/Microsoft.Web/sites/other")
        )
        self.assertEqual(len(_workload_paths([*_valid_resources(), unrelated])), 1)

    def test_duplicate_exact_proofs_deduplicate_deterministically(self) -> None:
        assignment = _azure_assignment()
        paths = _workload_paths([*_valid_resources(assignment=assignment), assignment])

        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["role_assignment_address"], "azurerm_role_assignment.audit_telemetry")

    def test_current_state_revalidation_refreshes_valid_proof_and_rejects_stale_state(self) -> None:
        def fixture() -> tuple[
            ResourceInventory,
            AzureDecorationContext,
            NormalizedResource,
            NormalizedResource,
            list[NormalizedResource],
        ]:
            inventory, context = _normalize(_valid_resources())
            workload = inventory.get_by_address("azurerm_linux_web_app.orders")
            diagnostic = inventory.get_by_address("azurerm_monitor_diagnostic_setting.audit")
            assert workload is not None
            assert diagnostic is not None
            return inventory, context, workload, diagnostic, list(inventory.resources)

        _inventory, context, workload, diagnostic, resources = fixture()
        current = current_app_service_diagnostic_setting_audit_telemetry_disruption_paths(
            workload,
            diagnostic,
            resources,
            context,
        )
        self.assertEqual(len(current), 1)

        inventory, context, workload, diagnostic, resources = fixture()
        role = inventory.get_by_address("azurerm_role_definition.audit_telemetry")
        assert role is not None
        role.set_metadata_field(
            AzureResourceMetadata.ROLE_DEFINITION_ACTIONS,
            [_AZURE_DELETE_DIAGNOSTIC, "Microsoft.Insights/DiagnosticSettings/Read"],
        )
        diagnostic.set_metadata_field(
            AzureResourceMetadata.DIAGNOSTIC_LOG_ANALYTICS_WORKSPACE_ID,
            None,
        )
        diagnostic.set_metadata_field(
            AzureResourceMetadata.DIAGNOSTIC_STORAGE_ACCOUNT_ID,
            _STORAGE_ID,
        )
        diagnostic.set_metadata_field(
            AzureResourceMetadata.DIAGNOSTIC_ENABLED_LOG_CATEGORY_GROUPS,
            [],
        )
        diagnostic.set_metadata_field(
            AzureResourceMetadata.DIAGNOSTIC_ENABLED_LOG_CATEGORIES,
            ["AppServiceAuditLogs"],
        )
        diagnostic.set_metadata_field(
            AzureResourceMetadata.DIAGNOSTIC_LOG_RECORDS,
            [{"category": "AppServiceAuditLogs"}],
        )
        refreshed = current_app_service_diagnostic_setting_audit_telemetry_disruption_paths(
            workload,
            diagnostic,
            resources,
            context,
        )
        self.assertEqual(len(refreshed), 1)
        self.assertEqual(refreshed[0]["destination_evidence"]["destination_basis"], "storage_account")
        self.assertEqual(
            refreshed[0]["audit_telemetry_relevance_evidence"]["relevance_basis"],
            "audit_security_category",
        )
        self.assertIn(
            "Microsoft.Insights/DiagnosticSettings/Read",
            refreshed[0]["authorization_grant"]["role_actions"],
        )

        for case in ("identity", "rbac", "target", "relevance", "destination"):
            with self.subTest(case=case):
                inventory, context, workload, diagnostic, resources = fixture()
                if case == "identity":
                    workload.set_metadata_field(AzureResourceMetadata.PRINCIPAL_ID, "replacement-principal")
                elif case == "rbac":
                    role = inventory.get_by_address("azurerm_role_definition.audit_telemetry")
                    assert role is not None
                    role.set_metadata_field(AzureResourceMetadata.ROLE_DEFINITION_ACTIONS, [])
                elif case == "target":
                    diagnostic.set_metadata_field(
                        AzureResourceMetadata.DIAGNOSTIC_SETTING_ID,
                        f"{_AZURE_WORKLOAD_ID}|replacement",
                    )
                elif case == "relevance":
                    diagnostic.set_metadata_field(
                        AzureResourceMetadata.DIAGNOSTIC_ENABLED_LOG_CATEGORY_GROUPS,
                        [],
                    )
                    diagnostic.set_metadata_field(
                        AzureResourceMetadata.DIAGNOSTIC_ENABLED_LOG_CATEGORIES,
                        ["AppServiceHTTPLogs"],
                    )
                    diagnostic.set_metadata_field(
                        AzureResourceMetadata.DIAGNOSTIC_LOG_RECORDS,
                        [{"category": "AppServiceHTTPLogs"}],
                    )
                else:
                    diagnostic.set_metadata_field(
                        AzureResourceMetadata.DIAGNOSTIC_LOG_ANALYTICS_WORKSPACE_ID,
                        None,
                    )
                self.assertEqual(
                    current_app_service_diagnostic_setting_audit_telemetry_disruption_paths(
                        workload,
                        diagnostic,
                        resources,
                        context,
                    ),
                    [],
                )

        _inventory, _context, workload, diagnostic, resources = fixture()
        lock_inventory = AzureNormalizer().normalize([_azure_management_lock(scope=_AZURE_DIAGNOSTIC_ID)])
        resources_with_lock = [*resources, *lock_inventory.resources]
        lock_context = AzureDecorationContext(index=AzureResourceIndexBuilder().build(resources_with_lock))
        self.assertEqual(
            current_app_service_diagnostic_setting_audit_telemetry_disruption_paths(
                workload,
                diagnostic,
                resources_with_lock,
                lock_context,
            ),
            [],
        )

    def test_stage_runs_after_identity_and_role_assignment_decoration(self) -> None:
        names = [stage.name for stage in default_azure_decoration_stages()]
        model = names.index("model_app_service_diagnostic_setting_audit_telemetry_disruption_paths")

        self.assertGreater(model, names.index("decorate_managed_identity_role_assignments"))


if __name__ == "__main__":
    unittest.main()
