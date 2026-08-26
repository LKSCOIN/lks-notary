#!/usr/bin/env python3
"""Index every LKS Notary payload on the LKSCOIN chain into the explorer DB.

Runs independently of the notary service and talks only to a node. That is the
point: the claim "anyone can scan the chain and find these proofs without us"
should be demonstrated by us doing exactly that, with code anyone can read.

    python3 scan_chain.py --from-height 995000
    python3 scan_chain.py            # resumes from notary_scan_state

Reorg handling: the last CONFIRMATIONS_SAFE blocks are rescanned every run and
rows are upserted, so a block replaced by a reorg drops out on the next pass.
"""
from __future__ import annotations

import argparse
import json
import os
import urllib.request
from datetime import datetime

import pymysql

MAGIC = "4c4b534e"          # "LKSN"
CONFIRMATIONS_SAFE = 20     # blocks re-checked on every run


def rpc(url: str, method: str, *params):
    request = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "1.0", "id": "scan", "method": method,
                         "params": list(params)}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        body = json.load(response)
    if body.get("error"):
        raise RuntimeError(body["error"])
    return body["result"]


def parse_payload(script_hex: str) -> tuple[int, int, str] | None:
    """Return (version, type, digest_hex) for our OP_RETURN outputs, else None.

    The script is OP_RETURN (0x6a) + pushdata(38) + payload, so the magic starts
    at byte 2. Anything else on the chain is somebody else's data and is
    ignored rather than mis-indexed.
    """
    if not script_hex.startswith("6a26"):      # OP_RETURN, push 38 bytes
        return None
    payload = script_hex[4:]
    if len(payload) != 76 or not payload.startswith(MAGIC):
        return None
    version = int(payload[8:10], 16)
    type_ = int(payload[10:12], 16)
    if version != 1 or type_ not in (1, 2):
        return None
    return version, type_, payload[12:]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rpc", default=os.getenv("LKS_RPC_URL_AUTH"),
                        help="http://user:password@127.0.0.1:3344")
    parser.add_argument("--db", default=os.getenv("EXPLORER_DB", "db_lkschain"))
    parser.add_argument("--db-user", default=os.getenv("EXPLORER_DB_USER", "notary"))
    parser.add_argument("--db-password", default=os.getenv("EXPLORER_DB_PASSWORD", ""))
    parser.add_argument("--from-height", type=int)
    args = parser.parse_args()

    connection = pymysql.connect(host="127.0.0.1", user=args.db_user,
                                 password=args.db_password, database=args.db,
                                 charset="utf8mb4", autocommit=False)
    cursor = connection.cursor()

    tip = rpc(args.rpc, "getblockcount")
    if args.from_height is not None:
        start = args.from_height
    else:
        cursor.execute("SELECT LastScannedNum FROM notary_scan_state WHERE ID = 1")
        row = cursor.fetchone()
        start = max(0, (row[0] if row else tip - 1000) - CONFIRMATIONS_SAFE)

    found = 0
    for height in range(start, tip + 1):
        block = rpc(args.rpc, "getblock", rpc(args.rpc, "getblockhash", height), 2)
        block_time = datetime.utcfromtimestamp(block["time"])
        for tx in block["tx"]:
            for out in tx.get("vout", []):
                parsed = parse_payload(out["scriptPubKey"]["hex"])
                if parsed is None:
                    continue
                version, type_, digest = parsed
                cursor.execute(
                    """INSERT INTO notary_onchain
                       (TxID, BlockNum, BlockHash, BlockTime, Version, Type, Digest)
                       VALUES (%s, %s, %s, %s, %s, %s, %s)
                       ON DUPLICATE KEY UPDATE
                         BlockNum = VALUES(BlockNum), BlockHash = VALUES(BlockHash),
                         BlockTime = VALUES(BlockTime)""",
                    (tx["txid"], height, block["hash"], block_time, version, type_, digest),
                )
                found += 1
        if height % 500 == 0:
            connection.commit()
            print(f"... {height}/{tip}, {found} payloads so far", flush=True)

    cursor.execute(
        """INSERT INTO notary_scan_state (ID, LastScannedNum) VALUES (1, %s)
           ON DUPLICATE KEY UPDATE LastScannedNum = VALUES(LastScannedNum)""",
        (tip,),
    )
    connection.commit()
    print(f"done: scanned {start}..{tip}, indexed {found} notary payloads")


if __name__ == "__main__":
    main()
