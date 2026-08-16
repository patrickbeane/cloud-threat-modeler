from __future__ import annotations

import types
import unittest
from typing import Literal, get_type_hints

from tfstride.providers.aws.message_removal_evidence import (
    AwsEcsSqsQueueMessagePurgePath,
    AwsEcsSqsReceivedMessageDeletionPath,
    AwsSqsMessageRemovalDeliveryEvidence,
)
from tfstride.providers.azure.message_removal_evidence import (
    AzureAppServiceServiceBusNamespaceMessageRemovalPath,
    AzureAppServiceServiceBusQueueMessageRemovalPath,
    AzureAppServiceServiceBusSubscriptionMessageRemovalPath,
    AzureServiceBusMessageRemovalDeliveryEvidence,
)
from tfstride.providers.gcp.message_removal_evidence import (
    GcpCloudRunPubsubProjectMessageAcknowledgementPath,
    GcpCloudRunPubsubSubscriptionMessageAcknowledgementPath,
    GcpPubsubMessageRemovalDeliveryEvidence,
)


class MessageRemovalEvidenceTests(unittest.TestCase):
    def test_aws_contract_discriminates_received_message_delete_from_purge(
        self,
    ) -> None:
        delete_hints = get_type_hints(AwsEcsSqsReceivedMessageDeletionPath)
        purge_hints = get_type_hints(AwsEcsSqsQueueMessagePurgePath)
        delivery_hints = get_type_hints(AwsSqsMessageRemovalDeliveryEvidence)

        self.assertEqual(
            delete_hints["operation"],
            Literal["sqs:DeleteMessage"],
        )
        self.assertEqual(
            delete_hints["prerequisite_operation"],
            Literal["sqs:ReceiveMessage"],
        )
        self.assertEqual(
            delete_hints["target_granularity"],
            Literal["queue_received_message_namespace"],
        )
        self.assertIs(delete_hints["receipt_handle_value"], types.NoneType)
        self.assertIn("receive_authorization", delete_hints)
        self.assertEqual(
            purge_hints["operation"],
            Literal["sqs:PurgeQueue"],
        )
        self.assertIs(purge_hints["prerequisite_operation"], types.NoneType)
        self.assertNotIn("receive_authorization", purge_hints)
        self.assertEqual(
            delivery_hints["removed_message_recovery_state"],
            Literal["not_established_by_modeled_sqs_delivery_controls"],
        )

    def test_gcp_contract_keeps_acknowledgement_scope_and_replay_separate(
        self,
    ) -> None:
        project_hints = get_type_hints(GcpCloudRunPubsubProjectMessageAcknowledgementPath)
        subscription_hints = get_type_hints(GcpCloudRunPubsubSubscriptionMessageAcknowledgementPath)
        delivery_hints = get_type_hints(GcpPubsubMessageRemovalDeliveryEvidence)

        self.assertEqual(
            subscription_hints["operation"],
            Literal["pubsub.subscriptions.consume"],
        )
        self.assertEqual(
            subscription_hints["target_granularity"],
            Literal["subscription_message_namespace"],
        )
        self.assertIs(
            subscription_hints["acknowledgement_id_value"],
            types.NoneType,
        )
        self.assertEqual(project_hints["scope_type"], Literal["project"])
        self.assertEqual(
            subscription_hints["scope_type"],
            Literal["subscription"],
        )
        self.assertEqual(
            delivery_hints["replay_authority_evaluated"],
            Literal[False],
        )
        self.assertEqual(
            delivery_hints["dead_letter_policy_is_acknowledgement_recovery"],
            Literal[False],
        )

    def test_azure_contract_preserves_receive_modes_and_native_ancestry(
        self,
    ) -> None:
        namespace_hints = get_type_hints(AzureAppServiceServiceBusNamespaceMessageRemovalPath)
        queue_hints = get_type_hints(AzureAppServiceServiceBusQueueMessageRemovalPath)
        subscription_hints = get_type_hints(AzureAppServiceServiceBusSubscriptionMessageRemovalPath)
        delivery_hints = get_type_hints(AzureServiceBusMessageRemovalDeliveryEvidence)

        self.assertEqual(
            namespace_hints["target_granularity"],
            Literal["namespace_message_namespace"],
        )
        self.assertEqual(
            queue_hints["target_granularity"],
            Literal["queue_message_namespace"],
        )
        self.assertEqual(
            subscription_hints["target_granularity"],
            Literal["subscription_message_namespace"],
        )
        self.assertIs(queue_hints["topic_address"], types.NoneType)
        self.assertEqual(subscription_hints["topic_address"], str)
        self.assertEqual(
            subscription_hints["receive_and_delete_capability"],
            Literal[True],
        )
        self.assertEqual(
            subscription_hints["peek_lock_complete_capability"],
            Literal[True],
        )
        self.assertIs(
            subscription_hints["complete_lock_token_value"],
            types.NoneType,
        )
        self.assertEqual(
            delivery_hints["removed_message_recovery_state"],
            Literal["not_established_by_modeled_service_bus_delivery_controls"],
        )


if __name__ == "__main__":
    unittest.main()
