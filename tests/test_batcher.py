from datetime import datetime, timedelta, timezone

from lks_notary.batcher import PendingLeaf, order_leaves, publish_batch
from lks_notary.merkle import root
from lks_notary.payload import decode


class FakeRpc:
    def __init__(self):
        self.sent = []

    def send_op_return(self, payload_hex, fee_rate=None):
        self.sent.append(payload_hex)
        return "f" * 64


def leaf(i, offset_seconds=0):
    return PendingLeaf(
        notarization_id=f"id-{i}",
        leaf_hash=bytes([i]) * 32,
        received_at=datetime(2026, 8, 25, tzinfo=timezone.utc) + timedelta(seconds=offset_seconds),
    )


def test_ordering_is_by_time_then_hash():
    a, b, c = leaf(3), leaf(1), leaf(2, offset_seconds=-1)
    assert [x.notarization_id for x in order_leaves([a, b, c])] == ["id-2", "id-1", "id-3"]


def test_empty_batch_publishes_nothing():
    rpc = FakeRpc()
    assert publish_batch([], rpc) is None
    assert rpc.sent == []


def test_published_payload_carries_the_root():
    leaves = [leaf(i, i) for i in range(1, 6)]
    rpc = FakeRpc()
    result = publish_batch(leaves, rpc)
    assert result.merkle_root == root([x.leaf_hash for x in order_leaves(leaves)])
    assert decode(bytes.fromhex(rpc.sent[0])).digest == result.merkle_root


def test_same_leaves_in_any_order_give_the_same_root():
    leaves = [leaf(i, i) for i in range(1, 6)]
    rpc_a, rpc_b = FakeRpc(), FakeRpc()
    assert publish_batch(leaves, rpc_a).merkle_root == \
           publish_batch(list(reversed(leaves)), rpc_b).merkle_root
