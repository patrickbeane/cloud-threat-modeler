# Public Workload Object-Storage Disruption and Recovery Paths

Object-storage analysis separates public-workload authority to mutate stored data from authority to delete it. The model preserves exact and bounded provider-native scopes without requiring a Terraform object resource for every target.

## Shared boundary

* Object writes and tag or metadata mutation produce Tampering paths.
* Logical object deletion, version deletion, and generation deletion produce object-level Denial of Service paths.
* Bucket and container deletion produce topology-level Denial of Service paths, separately from object deletion.
* Private workloads retain modeled authority paths but do not produce public-workload findings.
* Conditional, denied, incomplete, ambiguous, and unresolved authority is not promoted into a deterministic deletion path.
* Recovery evidence describes impact and compatibility; it does not establish that deletion will succeed or that recovery is guaranteed.

## Target granularity

Deletion paths retain the narrowest modeled target available:

* exact object or blob;
* exact bucket or container topology;
* bounded object or blob prefix;
* bucket- or container-wide object namespace;
* exact object version or generation;
* version or generation namespace beneath an object, prefix, bucket, or container.

These scopes come from provider-native authorization evidence. The model does not invent unmodeled object instances or claim that a parent scope identifies one concrete object.

## Provider-native recovery

| Provider | Native recovery boundary |
| --- | --- |
| AWS | `s3:DeleteObject` can create a delete marker when versioning is enabled; `s3:DeleteObjectVersion` targets retained versions or version namespaces. Object Lock, default retention, legal holds, and governance bypass remain compatibility evidence rather than proof of effective target retention or permanent deletion. |
| GCP | Logical deletion with Object Versioning enabled leaves the live generation noncurrent. Generation deletion does not receive protection from versioning; soft delete supplies the recovery mechanism when enabled. Unknown or unobserved recovery posture remains explicit uncertainty. |
| Azure | Current-blob deletion, blob-version deletion, and `permanentDelete` remain separate operations. HNS can make version deletion incompatible, while permanent deletion requires the feature and an exact compatible soft-deleted version or snapshot target. |

## Scope limits

This model does not cover account destruction, policy delegation, retention-policy mutation, successful runtime deletion or recovery, or consumers and object instances outside the Terraform plan. Provider-specific recovery controls remain plan-local and may describe defaults or posture without proving the state of an existing object version.

See [Cross-Provider Threat-Path Semantics](path-semantics.md) for the shared quiet-versus-promoted evidence rule, and the provider coverage maps ([AWS](../providers/aws.md), [GCP](../providers/gcp.md), [Azure](../providers/azure.md)) for current implementation scope.
