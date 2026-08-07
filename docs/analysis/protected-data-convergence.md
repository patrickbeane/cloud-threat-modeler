# Protected-Data Key-Authority Convergence

Protected-data convergence joins three independently modeled plan-evidence paths:

1. The workload's exact runtime identity and read or receive authority.
2. An exact protected-resource dependency on a customer-managed key.
3. Decrypt, unwrap, or equivalent provider-native key authority held by the same runtime identity for that same key.

Convergence records join identity, protected-resource, and key-authority evidence independently; provider-specific public plaintext-recovery findings additionally require deterministic public workload exposure.

## Current provider-native coverage

* **AWS**: ECS task roles reading S3 objects protected by an exact KMS key, including alias-resolved keys.
* **GCP**: Cloud Run service accounts reading GCS objects protected by an exact Cloud KMS CryptoKey.
* **Azure**: App Service or Function App managed identities reading Storage resources or receiving from Service Bus resources protected by an exact Key Vault key dependency, including account or namespace ancestry and versioned versus versionless key identity.

## What convergence does - and doesn't - mean

Convergence is an evidence join, not proof that plaintext is disclosed or that an application successfully retrieves data at runtime. Exact key, runtime-identity, protected-resource, and parent-ancestry mismatches remain nonconvergent. Denied or incompatible evidence stays quiet; condition-dependent, ambiguous, unresolved, unsupported, or incomplete expected relationships remain uncertainty where applicable. Out-of-plan access and consumers are not inferred.

Existing provider-specific public plaintext-recovery findings may be enriched with exact modeled dependent resources without changing their rule identities. Findings count unique readable or receivable protected resources separately from logical encryption dependencies while preserving provider-native authorization scope, aliases, key versions, ancestry, and operation-exact evidence.

Cross-provider parity tests pin these shared outcomes while ensuring that convergence records, findings, affected resources, and evidence remain provider-local.

See [Cross-Provider Threat-Path Semantics](path-semantics.md) for the shared cross-provider evidence model.
