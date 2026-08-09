# Public Workload Secret Integrity and Availability Paths

Public workload secret-management analysis models deterministic runtime authority to mutate or remove secrets, separately from secret delivery and plaintext access. A finding requires public workload exposure, the current runtime identity, an exact modeled secret target, and unconditional provider-native authorization. Explicit denies and incompatible lifecycle states stay quiet. Condition-dependent, incomplete, ambiguous, or unresolved expected relationships are not promoted and remain visible as uncertainty where the provider model can identify them.

## Provider-native operation boundaries

* **AWS**: ECS task roles can produce tampering paths for `PutSecretValue`, `UpdateSecret`, and `UpdateSecretVersionStage`, or disruption paths for `DeleteSecret`. Secrets Manager recovery-window values describe Terraform deletion posture and are not treated as runtime recovery authority.
* **GCP**: Cloud Run service accounts can produce tampering paths for secret-version creation, or disruption paths for version disablement, version destruction, and secret deletion. IAM remains project- or secret-scoped; version-destruction delay and version lifecycle state remain native recovery evidence.
* **Azure**: App Service system- or attached user-assigned identities can produce Key Vault secret value mutation, recoverable deletion, or ordered delete-plus-purge paths through the active RBAC or legacy access-policy model. Purge protection controls whether the permanent deletion sequence is compatible, while versioned and versionless secret identities remain distinct.

Tampering and availability findings are provider-owned and remain operation-exact. They establish modeled secret-integrity or secret-availability authority, not possession of secret payloads, successful runtime execution, or public disclosure of secret values. Cross-provider parity tests verify the shared threat outcomes while preserving each provider's native target, scope, identity, and recovery evidence.

See [Cross-Provider Threat-Path Semantics](path-semantics.md) for the shared cross-provider evidence model.
