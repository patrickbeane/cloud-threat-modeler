# Cross-Provider Threat-Path Semantics

`tfstride` runs the same analysis *shape* across AWS, GCP, and AzureRM - shared evidence vocabulary, shared parity tests - while keeping every finding provider-owned, because AWS IAM, GCP IAM, and Azure RBAC are not interchangeable systems. This doc explains that shared shape; see the provider docs ([AWS](../providers/aws.md), [GCP](../providers/gcp.md), [Azure](../providers/azure.md)) for what's actually modeled per cloud.

## The "quiet vs. promoted" rule

A relationship only becomes a finding when it is backed by deterministic modeled evidence. Exact symbolic first-apply references may qualify when resolution is unambiguous. Denied or incompatible evidence stays **quiet**; condition-dependent, ambiguous, unresolved, unsupported, or incomplete expected relationships are retained as uncertainty where the provider model can identify them. Out-of-plan relationships are not inferred. This applies consistently to:

* Workload-to-data mutation and read paths (e.g., an ECS task role, Cloud Run service account, or App Service managed identity reaching a data store)
* Cryptographic-operation paths (decrypt, unwrap, sign, MAC-generate), which additionally require compatible key capabilities and effective operation authorization
* Managed-key administration paths (disruption, authorization delegation), which additionally require exact modeled key or management-target resolution
* Messaging read paths, which require the corresponding exact receive/consume grant - modeled identity and provider-native receive or consume authority is not a guarantee of effective message retrieval after provider deny, network, or encryption controls
* Secret values themselves, which are never retained in evidence or reports

## Identity and workload data-plane paths are provider-local

Privileged identity assignment posture is normalized into a shared provider-neutral vocabulary for evidence and parity tests, but findings stay provider-owned:

* **AWS** distinguishes ECS execution-role secret delivery from task-role permissions, and connects public ECS services to exact Secrets Manager, S3, SNS/SQS, DynamoDB, and KMS grants.
* **GCP** connects public Cloud Run service accounts to exact Secret Manager, GCS, Pub/Sub, Firestore, and Cloud KMS grants.
* **Azure** connects public App Service or Function App managed identities to exact Key Vault, Storage Account/container, Service Bus, or Cosmos DB for NoSQL authorization.

## Managed-key dependencies

Managed-key dependency analysis preserves provider-native key, alias, version, and vault identity, then enriches disruption findings only with exact modeled encrypted dependents. Ambiguous, unresolved, or unsupported expected dependencies remain uncertainty; incompatible consumers stay quiet, and out-of-plan consumers are not inferred. Full detail: [Managed-Key Paths](managed-key-paths.md).

## Network telemetry and public edge protection are provider-local checks

Both are conceptually the same check, implemented against each provider's native primitive:

| Concept | AWS | GCP | Azure |
| --- | --- | --- | --- |
| Network telemetry | Modeled VPC Flow Logs | Subnet Flow Logs | Modeled Network Watcher flow logs for NSGs |
| Public edge protection | Modeled WAFv2 Web ACL associations for public ALBs | Cloud Armor policy references on public load-balancer backends | Firewall policy or enabled WAF configuration for public Application Gateway listeners |

## Condition narrowing

Condition narrowing focuses on high-signal, provider-specific authorization keys (for example AWS's `SourceArn`, `SourceAccount`, and `ExternalId`) rather than exhaustive coverage of every service-specific authorization condition.

## Subnet classification

Subnet classification prefers explicit route table associations when available, but does not model main-route-table inheritance or every routing edge case.
