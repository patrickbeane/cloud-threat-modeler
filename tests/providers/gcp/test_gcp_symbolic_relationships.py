from __future__ import annotations

import unittest
from pathlib import Path

from tfstride.input.terraform_plan import load_terraform_plan
from tfstride.models import (
    NormalizedResource,
    ResourceCategory,
    TerraformReferenceProvenance,
    TerraformReferenceResolution,
    TerraformReferenceResolutionState,
    TerraformReferenceTarget,
    TerraformResource,
)
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_decoration.symbolic_relationships import (
    ResolveGcpSymbolicRelationshipsStage,
)
from tfstride.providers.gcp.resource_decorator import GcpResourceDecorator
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_FIRST_APPLY_FIXTURE = _REPOSITORY_ROOT / "fixtures/gcp/sample_gcp_first_apply_symbolic_plan.json"


def _resource(
    address: str,
    resource_type: str,
    category: ResourceCategory,
    *,
    identifier: str | None = None,
    metadata: dict[object, object] | None = None,
    reference_resolutions: tuple[TerraformReferenceResolution, ...] = (),
) -> NormalizedResource:
    return NormalizedResource(
        address=address,
        provider="gcp",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        category=category,
        identifier=identifier,
        metadata=metadata or {},
        reference_resolutions=reference_resolutions,
    )


def _symbolic_resolution(
    path: tuple[str | int, ...],
    target_address: str,
    target_attribute: str = ".id",
) -> TerraformReferenceResolution:
    reference = f"{target_address}{target_attribute}"
    return TerraformReferenceResolution(
        path=path,
        state=TerraformReferenceResolutionState.SYMBOLIC,
        provenance=TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
        references=(reference,),
        targets=(TerraformReferenceTarget(address=target_address, reference=reference),),
    )


class GcpSymbolicRelationshipTests(unittest.TestCase):
    def test_first_apply_pubsub_subscription_resolves_topic(self) -> None:
        inventory = GcpNormalizer().normalize(load_terraform_plan(_FIRST_APPLY_FIXTURE).resources)

        direct = inventory.get_by_address("google_pubsub_subscription.direct")
        ambiguous = inventory.get_by_address("google_pubsub_subscription.ambiguous")
        assert direct is not None
        assert ambiguous is not None

        self.assertEqual(
            gcp_facts(direct).pubsub_topic_reference,
            "projects/tfstride-symbolic-fixture/topics/direct",
        )
        self.assertIsNone(gcp_facts(ambiguous).pubsub_topic_reference)

        runtime_binding = inventory.get_by_address("google_project_iam_binding.runtime")
        assert runtime_binding is not None
        self.assertEqual(
            gcp_facts(runtime_binding).get(GcpResourceMetadata.IAM_MEMBERS),
            [],
        )
        self.assertEqual(
            gcp_facts(runtime_binding).bindings[0]["members_state"],
            "unknown",
        )

    def test_project_and_key_ring_identity_resources_are_normalized(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                TerraformResource(
                    address="google_project.application",
                    mode="managed",
                    resource_type=GcpResourceType.PROJECT,
                    name="application",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={"project_id": "tfstride-demo"},
                ),
                TerraformResource(
                    address="google_kms_key_ring.application",
                    mode="managed",
                    resource_type=GcpResourceType.KMS_KEY_RING,
                    name="application",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={
                        "name": "application",
                        "project": "tfstride-demo",
                        "location": "global",
                    },
                ),
            ]
        )

        self.assertEqual(inventory.unsupported_resources, [])
        project = inventory.get_by_address("google_project.application")
        ring = inventory.get_by_address("google_kms_key_ring.application")
        assert project is not None
        assert ring is not None
        self.assertEqual(project.identifier, "tfstride-demo")
        self.assertEqual(
            gcp_facts(ring).kms_key_ring,
            "projects/tfstride-demo/locations/global/keyRings/application",
        )

    def test_cloud_run_runtime_service_account_resolves_symbolically(self) -> None:
        service_account = _resource(
            "google_service_account.runtime",
            GcpResourceType.SERVICE_ACCOUNT,
            ResourceCategory.IAM,
            identifier="runtime",
            metadata={
                GcpResourceMetadata.PROJECT: "tfstride-demo",
                GcpResourceMetadata.SERVICE_ACCOUNT_EMAIL: "runtime@tfstride-demo.iam.gserviceaccount.com",
            },
        )
        service = _resource(
            "google_cloud_run_v2_service.api",
            GcpResourceType.CLOUD_RUN_V2_SERVICE,
            ResourceCategory.COMPUTE,
            reference_resolutions=(
                _symbolic_resolution(
                    ("template", 0, "service_account"),
                    service_account.address,
                    ".email",
                ),
            ),
        )

        GcpResourceDecorator(stages=[ResolveGcpSymbolicRelationshipsStage()]).decorate([service_account, service])

        facts = gcp_facts(service)
        self.assertEqual(facts.service_account_email, "runtime@tfstride-demo.iam.gserviceaccount.com")
        self.assertEqual(facts.service_account_reference, service_account.address)
        self.assertEqual(
            facts.service_account_member,
            "serviceAccount:runtime@tfstride-demo.iam.gserviceaccount.com",
        )

    def test_cloud_run_service_account_id_or_member_is_not_promoted_to_email(self) -> None:
        service_account = _resource(
            "google_service_account.runtime",
            GcpResourceType.SERVICE_ACCOUNT,
            ResourceCategory.IAM,
            metadata={
                GcpResourceMetadata.SERVICE_ACCOUNT_EMAIL: "runtime@tfstride-demo.iam.gserviceaccount.com",
            },
        )
        id_reference = _resource(
            "google_cloud_run_v2_service.id_reference",
            GcpResourceType.CLOUD_RUN_V2_SERVICE,
            ResourceCategory.COMPUTE,
            reference_resolutions=(
                _symbolic_resolution(("template", 0, "service_account"), service_account.address, ".id"),
            ),
        )
        member_reference = _resource(
            "google_cloud_run_v2_service.member_reference",
            GcpResourceType.CLOUD_RUN_V2_SERVICE,
            ResourceCategory.COMPUTE,
            reference_resolutions=(
                _symbolic_resolution(
                    ("template", 0, "service_account"),
                    service_account.address,
                    ".member",
                ),
            ),
        )

        GcpResourceDecorator(stages=[ResolveGcpSymbolicRelationshipsStage()]).decorate(
            [service_account, id_reference, member_reference]
        )

        self.assertIsNone(gcp_facts(id_reference).service_account_email)
        self.assertIsNone(gcp_facts(member_reference).service_account_email)

    def test_secret_version_parent_requires_exact_id_reference(self) -> None:
        secret = _resource(
            "google_secret_manager_secret.orders",
            GcpResourceType.SECRET_MANAGER_SECRET,
            ResourceCategory.DATA,
            identifier="projects/tfstride-demo/secrets/orders",
            metadata={
                GcpResourceMetadata.NAME: "projects/tfstride-demo/secrets/orders",
                GcpResourceMetadata.PROJECT: "tfstride-demo",
                GcpResourceMetadata.SECRET_ID: "orders",
            },
        )
        exact = _resource(
            "google_secret_manager_secret_version.exact",
            GcpResourceType.SECRET_MANAGER_SECRET_VERSION,
            ResourceCategory.DATA,
            reference_resolutions=(_symbolic_resolution(("secret",), secret.address, ".id"),),
        )
        wrong_suffix = _resource(
            "google_secret_manager_secret_version.wrong",
            GcpResourceType.SECRET_MANAGER_SECRET_VERSION,
            ResourceCategory.DATA,
            reference_resolutions=(_symbolic_resolution(("secret",), secret.address, ".name"),),
        )

        GcpResourceDecorator(stages=[ResolveGcpSymbolicRelationshipsStage()]).decorate([secret, exact, wrong_suffix])

        self.assertEqual(
            gcp_facts(exact).secret_manager_version_resolved_secret_address,
            secret.address,
        )
        self.assertIsNone(gcp_facts(wrong_suffix).secret_manager_version_resolved_secret_address)

    def test_secret_iam_target_requires_exact_secret_id_reference(self) -> None:
        secret = _resource(
            "google_secret_manager_secret.orders",
            GcpResourceType.SECRET_MANAGER_SECRET,
            ResourceCategory.DATA,
            identifier="projects/tfstride-demo/secrets/orders",
            metadata={
                GcpResourceMetadata.NAME: "projects/tfstride-demo/secrets/orders",
                GcpResourceMetadata.PROJECT: "tfstride-demo",
                GcpResourceMetadata.SECRET_ID: "orders",
            },
        )
        exact = _resource(
            "google_secret_manager_secret_iam_member.exact",
            GcpResourceType.SECRET_MANAGER_SECRET_IAM_MEMBER,
            ResourceCategory.IAM,
            metadata={GcpResourceMetadata.IAM_SCOPE_REFERENCE_STATE: "unknown"},
            reference_resolutions=(_symbolic_resolution(("secret_id",), secret.address, ".secret_id"),),
        )
        wrong_suffix = _resource(
            "google_secret_manager_secret_iam_member.wrong",
            GcpResourceType.SECRET_MANAGER_SECRET_IAM_MEMBER,
            ResourceCategory.IAM,
            metadata={GcpResourceMetadata.IAM_SCOPE_REFERENCE_STATE: "unknown"},
            reference_resolutions=(_symbolic_resolution(("secret_id",), secret.address, ".id"),),
        )

        GcpResourceDecorator(stages=[ResolveGcpSymbolicRelationshipsStage()]).decorate([secret, exact, wrong_suffix])

        self.assertEqual(gcp_facts(exact).target_reference, secret.address)
        self.assertEqual(gcp_facts(exact).iam_scope_reference_state, "configured")
        self.assertIsNone(gcp_facts(wrong_suffix).target_reference)
        self.assertEqual(
            gcp_facts(wrong_suffix).iam_scope_reference_state,
            "unknown",
        )

    def test_kms_version_and_key_resolve_symbolic_parents(self) -> None:
        ring = _resource(
            "google_kms_key_ring.application",
            GcpResourceType.KMS_KEY_RING,
            ResourceCategory.DATA,
            identifier="projects/tfstride-demo/locations/global/keyRings/application",
            metadata={
                GcpResourceMetadata.NAME: "application",
                GcpResourceMetadata.PROJECT: "tfstride-demo",
                GcpResourceMetadata.KMS_KEY_RING: "projects/tfstride-demo/locations/global/keyRings/application",
            },
        )
        key = _resource(
            "google_kms_crypto_key.customer",
            GcpResourceType.KMS_CRYPTO_KEY,
            ResourceCategory.DATA,
            identifier="projects/tfstride-demo/locations/global/keyRings/application/cryptoKeys/customer",
            metadata={
                GcpResourceMetadata.NAME: "customer",
                GcpResourceMetadata.PROJECT: "tfstride-demo",
                GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE: (
                    "projects/tfstride-demo/locations/global/keyRings/application/cryptoKeys/customer"
                ),
                GcpResourceMetadata.KMS_KEY_RING: None,
            },
            reference_resolutions=(_symbolic_resolution(("key_ring",), ring.address, ".id"),),
        )
        version = _resource(
            "google_kms_crypto_key_version.primary",
            GcpResourceType.KMS_CRYPTO_KEY_VERSION,
            ResourceCategory.DATA,
            reference_resolutions=(_symbolic_resolution(("crypto_key",), key.address, ".id"),),
        )

        GcpResourceDecorator(stages=[ResolveGcpSymbolicRelationshipsStage()]).decorate([ring, key, version])

        key_facts = gcp_facts(key)
        version_facts = gcp_facts(version)
        self.assertEqual(
            key_facts.kms_key_ring,
            "projects/tfstride-demo/locations/global/keyRings/application",
        )
        self.assertEqual(
            version_facts.kms_crypto_key_version_crypto_key_reference,
            "projects/tfstride-demo/locations/global/keyRings/application/cryptoKeys/customer",
        )
        self.assertEqual(
            version_facts.kms_crypto_key_version_crypto_key_path,
            "projects/tfstride-demo/locations/global/keyRings/application/cryptoKeys/customer",
        )
        self.assertEqual(version_facts.project, "tfstride-demo")
        self.assertEqual(
            version_facts.kms_crypto_key_version_key_ring,
            "projects/tfstride-demo/locations/global/keyRings/application",
        )

    def test_kms_key_ring_name_is_not_promoted_to_key_ring_identity(self) -> None:
        ring = _resource(
            "google_kms_key_ring.application",
            GcpResourceType.KMS_KEY_RING,
            ResourceCategory.DATA,
            identifier="projects/tfstride-demo/locations/global/keyRings/application",
            metadata={
                GcpResourceMetadata.NAME: "application",
                GcpResourceMetadata.PROJECT: "tfstride-demo",
                GcpResourceMetadata.KMS_KEY_RING: None,
            },
        )
        key = _resource(
            "google_kms_crypto_key.customer",
            GcpResourceType.KMS_CRYPTO_KEY,
            ResourceCategory.DATA,
            reference_resolutions=(_symbolic_resolution(("key_ring",), ring.address, ".name"),),
        )

        GcpResourceDecorator(stages=[ResolveGcpSymbolicRelationshipsStage()]).decorate([ring, key])

        self.assertIsNone(gcp_facts(key).kms_key_ring)

    def test_kms_version_key_name_is_not_promoted_to_crypto_key_identity(self) -> None:
        key = _resource(
            "google_kms_crypto_key.customer",
            GcpResourceType.KMS_CRYPTO_KEY,
            ResourceCategory.DATA,
            identifier="projects/tfstride-demo/locations/global/keyRings/application/cryptoKeys/customer",
            metadata={
                GcpResourceMetadata.NAME: "customer",
                GcpResourceMetadata.PROJECT: "tfstride-demo",
            },
        )
        version = _resource(
            "google_kms_crypto_key_version.primary",
            GcpResourceType.KMS_CRYPTO_KEY_VERSION,
            ResourceCategory.DATA,
            reference_resolutions=(_symbolic_resolution(("crypto_key",), key.address, ".name"),),
        )

        GcpResourceDecorator(stages=[ResolveGcpSymbolicRelationshipsStage()]).decorate([key, version])

        facts = gcp_facts(version)
        self.assertIsNone(facts.kms_crypto_key_version_crypto_key_reference)
        self.assertIsNone(facts.kms_crypto_key_version_crypto_key_path)

    def test_project_iam_target_resolves_without_reconstructing_firestore_condition(self) -> None:
        project = _resource(
            "google_project.application",
            GcpResourceType.PROJECT,
            ResourceCategory.IAM,
            identifier="tfstride-demo",
            metadata={
                GcpResourceMetadata.NAME: "tfstride-demo",
                GcpResourceMetadata.PROJECT: "tfstride-demo",
            },
        )
        database = _resource(
            "google_firestore_database.orders",
            GcpResourceType.FIRESTORE_DATABASE,
            ResourceCategory.DATA,
            identifier="projects/tfstride-demo/databases/orders",
            metadata={
                GcpResourceMetadata.NAME: "orders",
                GcpResourceMetadata.PROJECT: "tfstride-demo",
                GcpResourceMetadata.FIRESTORE_DATABASE_NAME: "orders",
            },
        )
        project_iam = _resource(
            "google_project_iam_member.orders",
            GcpResourceType.PROJECT_IAM_MEMBER,
            ResourceCategory.IAM,
            metadata={
                GcpResourceMetadata.IAM_ROLE: "roles/datastore.viewer",
                GcpResourceMetadata.IAM_MEMBER: "serviceAccount:runtime@tfstride-demo.iam.gserviceaccount.com",
                GcpResourceMetadata.IAM_BINDINGS: [
                    {
                        "role": "roles/datastore.viewer",
                        "members": ["serviceAccount:runtime@tfstride-demo.iam.gserviceaccount.com"],
                    }
                ],
                GcpResourceMetadata.PROJECT: None,
                GcpResourceMetadata.IAM_SCOPE_REFERENCE_STATE: "unknown",
            },
            reference_resolutions=(
                _symbolic_resolution(("project",), project.address, ".project_id"),
                _symbolic_resolution(("condition", "expression"), database.address, ".name"),
            ),
        )

        GcpResourceDecorator(stages=[ResolveGcpSymbolicRelationshipsStage()]).decorate([project, database, project_iam])

        facts = gcp_facts(project_iam)
        self.assertEqual(facts.project, "tfstride-demo")
        self.assertFalse(project_iam.has_metadata_value(GcpResourceMetadata.IAM_CONDITION))
        self.assertNotIn("condition", facts.bindings[0])

    def test_singular_iam_member_resolves_only_the_member_field(self) -> None:
        service_account = _resource(
            "google_service_account.runtime",
            GcpResourceType.SERVICE_ACCOUNT,
            ResourceCategory.IAM,
            metadata={
                GcpResourceMetadata.SERVICE_ACCOUNT_EMAIL: "runtime@tfstride-demo.iam.gserviceaccount.com",
            },
        )
        iam_member = _resource(
            "google_project_iam_member.runtime",
            GcpResourceType.PROJECT_IAM_MEMBER,
            ResourceCategory.IAM,
            metadata={GcpResourceMetadata.IAM_ROLE: "roles/viewer"},
            reference_resolutions=(_symbolic_resolution(("member",), service_account.address, ".email"),),
        )

        GcpResourceDecorator(stages=[ResolveGcpSymbolicRelationshipsStage()]).decorate([service_account, iam_member])

        facts = gcp_facts(iam_member)
        self.assertEqual(
            facts.get(GcpResourceMetadata.IAM_MEMBER),
            "serviceAccount:runtime@tfstride-demo.iam.gserviceaccount.com",
        )
        self.assertEqual(
            facts.get(GcpResourceMetadata.IAM_MEMBERS),
            ["serviceAccount:runtime@tfstride-demo.iam.gserviceaccount.com"],
        )
        self.assertEqual(
            facts.bindings,
            [
                {
                    "role": "roles/viewer",
                    "members": ["serviceAccount:runtime@tfstride-demo.iam.gserviceaccount.com"],
                }
            ],
        )

    def test_firestore_condition_candidate_does_not_create_condition(self) -> None:
        database = _resource(
            "google_firestore_database.unknown",
            GcpResourceType.FIRESTORE_DATABASE,
            ResourceCategory.DATA,
            metadata={GcpResourceMetadata.FIRESTORE_DATABASE_NAME: "unknown"},
        )
        project_iam = _resource(
            "google_project_iam_member.unknown_database",
            GcpResourceType.PROJECT_IAM_MEMBER,
            ResourceCategory.IAM,
            metadata={
                GcpResourceMetadata.IAM_ROLE: "roles/datastore.viewer",
                GcpResourceMetadata.IAM_BINDINGS: [
                    {"role": "roles/datastore.viewer", "members": ["user:test@example.com"]}
                ],
            },
            reference_resolutions=(_symbolic_resolution(("condition", "expression"), database.address, ".name"),),
        )

        GcpResourceDecorator(stages=[ResolveGcpSymbolicRelationshipsStage()]).decorate([database, project_iam])

        self.assertFalse(project_iam.has_metadata_value(GcpResourceMetadata.IAM_CONDITION))

    def test_concrete_kms_version_parent_blocks_symbolic_enrichment(self) -> None:
        concrete_key = _resource(
            "google_kms_crypto_key.concrete",
            GcpResourceType.KMS_CRYPTO_KEY,
            ResourceCategory.DATA,
            identifier="projects/tfstride-demo/locations/global/keyRings/concrete/cryptoKeys/data",
            metadata={
                GcpResourceMetadata.NAME: "data",
                GcpResourceMetadata.PROJECT: "tfstride-demo",
                GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE: (
                    "projects/tfstride-demo/locations/global/keyRings/concrete/cryptoKeys/data"
                ),
                GcpResourceMetadata.KMS_KEY_RING: ("projects/tfstride-demo/locations/global/keyRings/concrete"),
            },
        )
        symbolic_key = _resource(
            "google_kms_crypto_key.symbolic",
            GcpResourceType.KMS_CRYPTO_KEY,
            ResourceCategory.DATA,
            identifier="projects/tfstride-demo/locations/global/keyRings/symbolic/cryptoKeys/data",
            metadata={
                GcpResourceMetadata.NAME: "data",
                GcpResourceMetadata.PROJECT: "tfstride-demo",
                GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE: (
                    "projects/tfstride-demo/locations/global/keyRings/symbolic/cryptoKeys/data"
                ),
                GcpResourceMetadata.KMS_KEY_RING: ("projects/tfstride-demo/locations/global/keyRings/symbolic"),
            },
        )
        version = _resource(
            "google_kms_crypto_key_version.primary",
            GcpResourceType.KMS_CRYPTO_KEY_VERSION,
            ResourceCategory.DATA,
            metadata={
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_CRYPTO_KEY_REFERENCE: (
                    "projects/tfstride-demo/locations/global/keyRings/concrete/cryptoKeys/data"
                ),
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_CRYPTO_KEY_PATH: (
                    "projects/tfstride-demo/locations/global/keyRings/concrete/cryptoKeys/data"
                ),
            },
            reference_resolutions=(_symbolic_resolution(("crypto_key",), symbolic_key.address, ".id"),),
        )

        GcpResourceDecorator(stages=[ResolveGcpSymbolicRelationshipsStage()]).decorate(
            [concrete_key, symbolic_key, version]
        )

        facts = gcp_facts(version)
        self.assertEqual(
            facts.kms_crypto_key_version_crypto_key_reference,
            "projects/tfstride-demo/locations/global/keyRings/concrete/cryptoKeys/data",
        )
        self.assertIsNone(facts.project)
        self.assertIsNone(facts.kms_crypto_key_version_key_ring)

    def test_ambiguous_and_wrong_symbolic_relationships_remain_unresolved(self) -> None:
        topic = _resource(
            "google_pubsub_topic.orders",
            GcpResourceType.PUBSUB_TOPIC,
            ResourceCategory.DATA,
            identifier="orders",
            metadata={
                GcpResourceMetadata.NAME: "orders",
                GcpResourceMetadata.PROJECT: "tfstride-demo",
            },
        )
        other_topic = _resource(
            "google_pubsub_topic.other",
            GcpResourceType.PUBSUB_TOPIC,
            ResourceCategory.DATA,
            identifier="other",
            metadata={
                GcpResourceMetadata.NAME: "other",
                GcpResourceMetadata.PROJECT: "tfstride-demo",
            },
        )
        subscription = _resource(
            "google_pubsub_subscription.orders",
            GcpResourceType.PUBSUB_SUBSCRIPTION,
            ResourceCategory.DATA,
            reference_resolutions=(
                TerraformReferenceResolution(
                    path=("topic",),
                    state=TerraformReferenceResolutionState.AMBIGUOUS,
                    provenance=TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
                    targets=(
                        TerraformReferenceTarget(
                            address=topic.address,
                            reference=f"{topic.address}.id",
                        ),
                        TerraformReferenceTarget(
                            address=other_topic.address,
                            reference=f"{other_topic.address}.id",
                        ),
                    ),
                ),
            ),
        )
        wrong_suffix = _resource(
            "google_pubsub_subscription.wrong",
            GcpResourceType.PUBSUB_SUBSCRIPTION,
            ResourceCategory.DATA,
            reference_resolutions=(_symbolic_resolution(("topic",), topic.address, ".project"),),
        )
        nested_topic = _resource(
            "google_pubsub_subscription.nested",
            GcpResourceType.PUBSUB_SUBSCRIPTION,
            ResourceCategory.DATA,
            reference_resolutions=(_symbolic_resolution(("dead_letter_policy", 0, "topic"), topic.address),),
        )

        GcpResourceDecorator(stages=[ResolveGcpSymbolicRelationshipsStage()]).decorate(
            [topic, other_topic, subscription, wrong_suffix, nested_topic]
        )

        self.assertIsNone(gcp_facts(subscription).pubsub_topic_reference)
        self.assertIsNone(gcp_facts(wrong_suffix).pubsub_topic_reference)
        self.assertIsNone(gcp_facts(nested_topic).pubsub_topic_reference)


if __name__ == "__main__":
    unittest.main()
