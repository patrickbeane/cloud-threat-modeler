from __future__ import annotations

from typing import Protocol

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.resource_decoration.artifact_registry_write_paths import (
    ModelCloudRunArtifactRegistryWritePathsStage,
)
from tfstride.providers.gcp.resource_decoration.cloud_run_firestore_access_paths import (
    ModelCloudRunFirestoreAccessPathsStage,
)
from tfstride.providers.gcp.resource_decoration.cloud_run_firestore_database_topology_destruction_paths import (
    ModelCloudRunFirestoreDatabaseTopologyDestructionPathsStage,
)
from tfstride.providers.gcp.resource_decoration.cloud_run_firestore_entity_deletion_paths import (
    ModelCloudRunFirestoreEntityDeletionPathsStage,
)
from tfstride.providers.gcp.resource_decoration.cloud_run_gcs_access_paths import (
    ModelCloudRunGcsAccessPathsStage,
)
from tfstride.providers.gcp.resource_decoration.cloud_run_gcs_bucket_topology_destruction_paths import (
    ModelCloudRunGcsBucketTopologyDestructionPathsStage,
)
from tfstride.providers.gcp.resource_decoration.cloud_run_gcs_object_deletion_paths import (
    ModelCloudRunGcsObjectDeletionPathsStage,
)
from tfstride.providers.gcp.resource_decoration.cloud_run_gcs_protected_data_convergence import (
    ModelCloudRunGcsProtectedDataConvergenceStage,
)
from tfstride.providers.gcp.resource_decoration.cloud_run_kms_operation_paths import (
    ModelCloudRunKmsManagementPathsStage,
    ModelCloudRunKmsOperationPathsStage,
)
from tfstride.providers.gcp.resource_decoration.cloud_run_logging_sink_audit_telemetry_disruption_paths import (
    ModelCloudRunLoggingSinkAuditTelemetryDisruptionPathsStage,
)
from tfstride.providers.gcp.resource_decoration.cloud_run_pubsub_access_paths import (
    ModelCloudRunPubsubAccessPathsStage,
)
from tfstride.providers.gcp.resource_decoration.cloud_run_pubsub_message_removal_paths import (
    ModelCloudRunPubsubMessageRemovalPathsStage,
)
from tfstride.providers.gcp.resource_decoration.cloud_run_pubsub_topology_destruction_paths import (
    ModelCloudRunPubsubTopologyDestructionPathsStage,
)
from tfstride.providers.gcp.resource_decoration.cloud_run_secret_access_paths import (
    ModelCloudRunSecretAccessPathsStage,
)
from tfstride.providers.gcp.resource_decoration.cloud_run_secret_management_paths import (
    ModelCloudRunSecretManagementPathsStage,
    NormalizeSecretManagerIamPostureStage,
    NormalizeSecretManagerVersionPostureStage,
)
from tfstride.providers.gcp.resource_decoration.firestore_iam import NormalizeFirestoreIamPostureStage
from tfstride.providers.gcp.resource_decoration.iam_assignment import NormalizeIamAssignmentPostureStage
from tfstride.providers.gcp.resource_decoration.iam_bindings import DecorateSensitiveIamBindingsStage
from tfstride.providers.gcp.resource_decoration.kms_encryption_dependencies import (
    ResolveGcpKmsEncryptionDependenciesStage,
)
from tfstride.providers.gcp.resource_decoration.kms_iam import NormalizeKmsIamPostureStage
from tfstride.providers.gcp.resource_decoration.kms_versions import NormalizeKmsCryptoKeyVersionPostureStage
from tfstride.providers.gcp.resource_decoration.load_balancer import DeriveLoadBalancerReachabilityStage
from tfstride.providers.gcp.resource_decoration.network_posture import DeriveNetworkPostureStage
from tfstride.providers.gcp.resource_decoration.public_exposure import DerivePublicExposureStage
from tfstride.providers.gcp.resource_decoration.symbolic_relationships import ResolveGcpSymbolicRelationshipsStage
from tfstride.providers.gcp.resource_decoration.workload_identity_federation import (
    ModelWorkloadIdentityFederationTrustPathsStage,
)
from tfstride.providers.gcp.resource_index import GcpDecorationContext


class GcpDecorationStage(Protocol):
    name: str

    def apply(self, resources: list[NormalizedResource], context: GcpDecorationContext) -> None:
        """Apply one ordered GCP resource decoration step."""
        ...


def default_gcp_decoration_stages() -> tuple[GcpDecorationStage, ...]:
    return (
        ResolveGcpSymbolicRelationshipsStage(),
        DeriveLoadBalancerReachabilityStage(),
        DeriveNetworkPostureStage(),
        DerivePublicExposureStage(),
        DecorateSensitiveIamBindingsStage(),
        ModelCloudRunLoggingSinkAuditTelemetryDisruptionPathsStage(),
        NormalizeSecretManagerVersionPostureStage(),
        NormalizeSecretManagerIamPostureStage(),
        NormalizeKmsIamPostureStage(),
        NormalizeKmsCryptoKeyVersionPostureStage(),
        ResolveGcpKmsEncryptionDependenciesStage(),
        ModelCloudRunKmsOperationPathsStage(),
        ModelCloudRunKmsManagementPathsStage(),
        NormalizeFirestoreIamPostureStage(),
        ModelCloudRunFirestoreAccessPathsStage(),
        ModelCloudRunFirestoreEntityDeletionPathsStage(),
        ModelCloudRunFirestoreDatabaseTopologyDestructionPathsStage(),
        ModelCloudRunGcsAccessPathsStage(),
        ModelCloudRunGcsObjectDeletionPathsStage(),
        ModelCloudRunGcsBucketTopologyDestructionPathsStage(),
        ModelCloudRunGcsProtectedDataConvergenceStage(),
        ModelCloudRunPubsubAccessPathsStage(),
        ModelCloudRunPubsubTopologyDestructionPathsStage(),
        ModelCloudRunPubsubMessageRemovalPathsStage(),
        ModelCloudRunSecretAccessPathsStage(),
        ModelCloudRunSecretManagementPathsStage(),
        ModelCloudRunArtifactRegistryWritePathsStage(),
        ModelWorkloadIdentityFederationTrustPathsStage(),
        NormalizeIamAssignmentPostureStage(),
    )
