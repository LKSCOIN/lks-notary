# LKS Notary

Notarization service that anchors document hashes to the LKSCOIN blockchain.
The document never leaves the client: only its SHA-256 is sent, aggregated into
a Merkle tree and published on chain as a 38-byte `OP_RETURN`.

Technical plan: `LKS_NOTARY_TECHNICAL_PLAN.md` (LKS Foundation).

## Status

Scaffold. The core primitives are implemented and tested; persistence,
OpenTimestamps anchoring and the public verification page are next.

Full cycle implemented: submit a hash, batch it, publish the Merkle root on
chain, follow it to confirmation, anchor it to Bitcoin, and verify it from a
browser or from a single-file script that trusts nobody.

| Component | State |
|---|---|
| JCS canonicalization (RFC 8785 subset) | done, tested |
| Merkle tree with odd-leaf promotion | done, tested |
| Leaf construction | done, tested |
| 38-byte on-chain payload | done, tested |
| Batcher | done, tested |
| Watcher (confirmations, ChainLock) | done |
| OpenTimestamps anchoring to Bitcoin | done, via the official `ots` client |
| LKSCOIN RPC client | done, gate A-1 passed on mainnet |
| API (`/notarize`, `/verify`, `/lookup`, `/health`) | done |
| MariaDB schema + hash-chained audit log | done |
| Public verification page (hashing in the browser) | done |
| `lks_verify.py` independent verifier | done, agreement with the service tested in CI |
| Chain scanner for the explorer | done |
| PDF certificate with QR code | not started |
| Rate limiting per API key | nginx only, per-key limit not started |
| LKS Log (streams, seals, agent and verifier) | done, tested end to end with a fake node; not yet run on mainnet |

## On-chain format

```
offset  len  field
0       4    magic    "LKSN"
4       1    version  0x01
5       1    type     0x01 batch Merkle root | 0x02 single notarization
6       32   payload  SHA-256 digest
```

38 bytes, well inside `MAX_OP_RETURN_RELAY` (83), which is the same on LKSCOIN
3.3.0, 4.17.x and 5.18.x. Field-tested on mainnet on 25 August 2026: accepted
without any policy change, mined in the first block, fee 0.0000239 LKS.

The magic prefix means anyone can scan the chain and index every notarization
without using this service, which is the point: the proof must outlive us.

## Merkle rule that differs from Bitcoin

An odd node is **promoted** to the next level, never duplicated. Bitcoin's
duplication rule (CVE-2012-2459) lets two different leaf sets share a root,
which would allow an inclusion proof for a document that was never notarized.
Any independent verifier must implement promotion.

## Storage

MariaDB, reusing the server that already runs the explorer and the site. The
notary lives in its own database (`lks_notary`) and never writes to the
explorer's: the two have different lifecycles and different blast radius.

One table does go into the explorer database — `notary_onchain`, filled by
`scripts/scan_chain.py` reading blocks straight from a node. It exists so the
public explorer can list notarizations without asking the notary service
anything, and so the index can be rebuilt from the chain by anyone. The
explorer's own `vout` table cannot serve that purpose: it stores address and
amount, and an OP_RETURN output has neither.

## Service node requirements

A LKSCOIN Core node with:

```
txindex=1
fallbackfee=0.0001
```

`fallbackfee` is not optional. LKSCOIN's mempool is usually empty, so automatic
fee estimation fails and `fundrawtransaction` returns *"Fee estimation failed.
Fallbackfee is disabled."* — the batcher would stall.

## Development

```bash
pip install -e ".[dev]"
pytest -q
docker compose up -d db      # PostgreSQL with the schema loaded
uvicorn lks_notary.api:app --reload
```

## What VALID means

`lks_verify.py` and `lks_log.py` say VALID only when a node you chose confirmed that a
transaction in a block carries the root. Without `--rpc` the answer is CONSISTENT, exit
status 2: the arithmetic adds up, but it runs over numbers the certificate supplies, and
anyone can invent a certificate that adds up. Scripts that treated exit status 0 from a
run without `--rpc` as success must add a node, or accept 2.

The verification page recomputes the record and the Merkle root in the browser, but the
blockchain and Bitcoin entries it shows come from this service, and it says so.

## LKS Log

Seals system and activity logs, as a layer over the notary primitive like Trace:
one batcher, one watcher, one Bitcoin anchor.

```
log lines            on the customer's machine, never sent
  | salted fingerprints, Merkle tree     lks_log.py
entries_root
  | canonical seal, chained to the previous one
seal_hash            what reaches the service
  | an ordinary notarisation, one leaf of the batch tree
batch root           OP_RETURN on LKSCOIN, then OpenTimestamps on Bitcoin
```

`lks_log.py` is both agent and verifier: one file, standard library only, like
`lks_verify.py`. `tests/test_log.py` holds it to the service byte for byte.

```bash
export LKS_LOG_API_KEY=...
python3 lks_log.py init --state /var/lib/lks-log --name web-1 --source /var/log/auth.log
python3 lks_log.py run --state /var/lib/lks-log

python3 lks_log.py verify-period --state /var/lib/lks-log
python3 lks_log.py prove --state /var/lib/lks-log --text "session opened" -o entry.json
python3 lks_log.py verify-proof --proof entry.json --rpc http://user:pass@127.0.0.1:3344
```

Pass `--certificates --rpc <node>` to `verify-period` for the full check. Exit status:
0 VALID, 1 INVALID, 2 anything short of that, either lines that could not be checked or
seals not confirmed on a node. Monitoring that only cares about tampering can treat 1
as the alarm; 2 is what a run without a node always returns.

Behaviour worth knowing:

* **An empty batch is still a seal.** Otherwise a stopped agent and a quiet system
  would look the same. A pause longer than two intervals is reported as a gap, based
  on `received_at`, which is part of the notarised record.
* **Proofs lag the interval.** A seal is provable when its batch is mined, so the
  window in which a line is unprotected is the agent's interval plus
  `BATCH_INTERVAL_SECONDS`. Sealing every minute does little while batches go out
  every ten.
* **A replaced file is INCOMPLETE, not INVALID.** If no line matches and the first
  bytes differ, it cannot be told apart from rotation. It is never VALID, and
  `--alias` points the check at the rotated copy.
* **The agent reads files.** Send syslog to a file first. Lines written to the old
  file between the last seal and a rotation are missed unless the rotation hook runs
  `seal`.
* **The state directory matters.** Without it the seals stand, but single lines can
  no longer be proved. Back it up with the logs.
* **Write rights.** A stream belongs to the API key that created it, and there is no
  anonymous tier. Whoever holds that key can append false seals, but cannot replace
  ones already accepted.

## What this is not

A qualified electronic timestamp under eIDAS. It is computer evidence: proof
that a hash existed at a given block height, verifiable by anyone against any
LKSCOIN node, and — once OpenTimestamps anchoring lands — against Bitcoin too.
