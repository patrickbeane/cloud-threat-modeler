# Public Workload Structured-Data Disruption and Recovery Paths

Structured-data analysis separates public-workload authority to mutate records from authority to delete them. The model preserves provider-native table, database, account, and container scopes without inventing item, entity, or document instances.

## Shared boundary

* Create, update, replace, and upsert authority produces Tampering paths.
* Item or entity deletion authority produces Denial of Service paths.
* One workload may produce both findings when both operation families are deterministic.
* Private workloads retain modeled deletion paths but do not produce public-workload findings.
* Deletion-only operations are excluded from mutation evidence.
* Conditional, denied, incomplete, ambiguous, unresolved, and unsupported authority is not promoted into a deterministic deletion path.

## Target granularity

Deletion paths retain exact provider-native namespaces rather than inventing records:

* AWS DynamoDB: exact table item namespace;
* GCP Firestore: exact database entity namespace or database bulk-entity namespace, with project- or exact-database-conditioned IAM evidence;
* Azure Cosmos DB for NoSQL: account, database, or container item namespace.

Whole-table, database, account, container, and ARM/control-plane destruction are outside this path family. Policy delegation and retention-policy mutation are also separate concerns.

## Provider-native recovery

| Provider | Native recovery boundary |
| --- | --- |
| AWS | DynamoDB point-in-time recovery is retained as recovery evidence for table item deletion; unknown or unobserved posture qualifies impact without proving item-level restoration. |
| GCP | Firestore point-in-time recovery and native historical-version posture remain provider-native evidence; unknown recovery stays unknown and does not suppress deterministic deletion authority. |
| Azure | Cosmos DB continuous, periodic, provider-default, and unknown backup posture remain distinct; backup evidence qualifies impact without proving successful restore or immediate item-level undo. |

Recovery evidence does not establish successful deletion, successful restoration, or guaranteed runtime recovery. It also does not infer out-of-plan records or downstream item instances.

See [Cross-Provider Threat-Path Semantics](path-semantics.md) for the shared quiet-versus-promoted rule, and the provider coverage maps ([AWS](../providers/aws.md), [GCP](../providers/gcp.md), [Azure](../providers/azure.md)) for current implementation scope.
