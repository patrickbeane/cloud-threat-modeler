# Public Workload Messaging Disclosure and Disruption Paths

Messaging analysis separates authority to send messages, receive their contents, and remove them. Findings remain provider-owned and preserve exact runtime identity, authorization scope, and consumable target ancestry.

## Shared boundary

* Send or publish authority produces Tampering paths.
* Receive or pull authority produces Information Disclosure paths.
* Delete, acknowledge, complete, or purge authority produces Denial of Service paths.
* One workload may produce multiple findings when the corresponding operation families are deterministic.
* Private workloads retain modeled paths but do not produce public-workload findings.
* Conditional, denied, incomplete, ambiguous, incompatible, or unresolved authority is not promoted into a deterministic path.

## Provider-native removal

| Provider | Removal boundary |
| --- | --- |
| AWS | ECS `DeleteMessage` requires the same task role to receive from the exact SQS queue; the receipt handle remains a runtime source. `PurgeQueue` independently establishes queue-wide removal authority. |
| GCP | Cloud Run `pubsub.subscriptions.consume` establishes disclosure and acknowledgement authority only for exact modeled pull subscriptions. Consumer-project scope and cross-project topic ancestry remain distinct. |
| Azure | App Service Service Bus receive authority establishes ReceiveAndDelete and PeekLock-completion capability for exact queues or topic subscriptions. Namespace RBAC fans out only to modeled consumable children; entity status and auto-forwarding remain runtime compatibility gates. |

## Delivery and replay evidence

SQS retention and redrive, Pub/Sub retention and acknowledged-message replay, and Service Bus TTL, lock, delivery-count, and dead-letter posture qualify impact only. They do not prove payload retrieval, successful removal, replay, restoration, or recovery. The model does not invent receipt handles, acknowledgement IDs, lock tokens, payloads, or operation outcomes.

## Scope limits

Queue, topic, subscription, and namespace destruction remain outside this path family. Broad grants fan out only to exact modeled consumable targets; out-of-plan message instances and runtime delivery mode selection are not inferred.

See [Cross-Provider Threat-Path Semantics](path-semantics.md) for the shared quiet-versus-promoted rule, and the provider coverage maps ([AWS](../providers/aws.md), [GCP](../providers/gcp.md), [Azure](../providers/azure.md)) for current implementation scope.
