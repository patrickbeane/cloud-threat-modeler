# Managed-Key Paths

Managed-key analysis separates cryptographic authority, administrative authority, and encrypted-resource dependencies while preserving each provider's native key and authorization model.

## Cryptographic-operation authority

Public workload paths model deterministic authority for operations with an immediate threat interpretation:

* Decrypt and unwrap operations establish Information Disclosure potential.
* Signing and MAC-generation operations establish Spoofing potential.
* Encrypt, wrap, verify, and public-key retrieval remain quiet unless connected to a stronger modeled threat.

An authorization path establishes operation authority, not possession of useful ciphertext, plaintext disclosure, or successful use of a generated authenticator.

## Managed-key administration

Administrative paths distinguish:

* Key disablement, deletion, destruction, or imported-material removal as Denial of Service potential.
* Grant, policy, IAM, RBAC, or access-model mutation as Elevation of Privilege potential.

Authorization that depends on unevaluated conditions, incomplete policy evidence, incompatible lifecycle state, or unresolved identities fails closed. Explicit denies remain deterministically unavailable. Recovery windows, version lifecycle, purge protection, and authorization scope remain provider-native evidence.

## Encrypted-resource dependencies

Dependency analysis tracks supported encrypted resources to exact provider-native keys:

* **AWS** resolves KMS keys and aliases for supported encryption fields.
* **GCP** resolves CMEK CryptoKeys while keeping CryptoKeyVersion lifecycle separate.
* **Azure** preserves versioned versus versionless Key Vault identities.

Public disruption findings can use those reverse-indexed dependencies to report exact modeled downstream resources and unique dependency counts.

## Conservative by design

The blast-radius enrichment is intentionally conservative:

* Project, account, subscription, resource-group, vault, ring, and key scope remain provider-specific.
* Unresolved or ambiguous dependencies are retained as uncertainty.
* Out-of-plan consumers are not inferred.
* Unsupported resources are skipped and called out in the report.

See [Cross-Provider Threat-Path Semantics](path-semantics.md) for how this fits the shared cross-provider evidence model, and each provider doc ([AWS](../providers/aws.md), [GCP](../providers/gcp.md), [Azure](../providers/azure.md)) for current provider-specific resource, key, and rule-family coverage.
