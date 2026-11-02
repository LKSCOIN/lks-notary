#!/usr/bin/env python3
"""lks-verify -- independent verifier for LKS Notary certificates.

Standard library only, single file, no dependency on the notary service beyond
fetching the certificate. Copy it anywhere and it keeps working; that is the
point of publishing it.

What it checks:

  1. the file you hold hashes to the document hash in the certificate;
  2. that hash, and the other stated fields, are the ones in the canonical record;
  3. the Merkle leaf recomputes from the canonical record;
  4. the Merkle root recomputes from the leaf and the inclusion path;
  5. optionally, against a LKSCOIN node of *your* choice, that the transaction
     really carries that root in an OP_RETURN output, and how deeply it is
     buried.

Nothing here trusts the notary service. Steps 1-4 are pure arithmetic; step 5
asks a node you pick, and only step 5 ties the certificate to the chain.

Exit status: 0 VALID, confirmed on a node; 1 INVALID, a check failed; 2 CONSISTENT,
nothing failed but the chain was not confirmed, because --rpc was not given, the
node could not be reached or the batch is not yet in a block.

    lks-verify --certificate https://api.lkschain.io/api/v1/verify/<id> --file contract.pdf
    lks-verify --certificate cert.json --rpc http://user:pass@127.0.0.1:3344
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import urllib.request
from typing import Any
from urllib.parse import urlsplit, urlunsplit

MAGIC = b"LKSN"
USER_AGENT = "lks-verify/1.0"
EXIT_VALID, EXIT_INVALID, EXIT_UNCONFIRMED = 0, 1, 2
OK, BAD, INFO = "\033[32m✔\033[0m", "\033[31m✘\033[0m", "\033[90m•\033[0m"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def load_certificate(source: str) -> dict[str, Any]:
    if source.startswith(("http://", "https://")):
        # The public service sits behind Cloudflare, which answers 403 to urllib's
        # default User-Agent.
        request = urllib.request.Request(source, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    with open(source, "rb") as handle:
        return json.load(handle)


def split_credentials(url: str) -> tuple[str, dict[str, str]]:
    """Move ``user:password@`` out of the URL and into a Basic auth header.

    urllib does not understand credentials embedded in a URL: it hands the
    whole ``user:pass@host`` to the DNS resolver, which fails with an obscure
    idna error. Node RPC URLs are almost always written that way, so we handle
    it here instead of asking the user to.
    """
    parts = urlsplit(url)
    headers = {"Content-Type": "application/json"}
    netloc = parts.netloc
    if "@" in netloc:
        credentials, netloc = netloc.rsplit("@", 1)
        token = base64.b64encode(credentials.encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment)), headers


def rpc_call(url: str, method: str, *params: Any) -> Any:
    endpoint, headers = split_credentials(url)
    request = urllib.request.Request(
        endpoint,
        data=json.dumps({"jsonrpc": "1.0", "id": "lks-verify",
                         "method": method, "params": list(params)}).encode(),
        headers=headers,
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        body = json.load(response)
    if body.get("error"):
        raise RuntimeError(body["error"])
    return body["result"]


def record_mismatches(cert: dict[str, Any]) -> list[str]:
    """Fields the certificate states that differ from the record that was hashed.

    Only ``canonical_record`` is covered by the proof; everything else in the file
    is unproved text. Without this check, a genuine proof for one document could
    be given another document's hash and still add up.
    """
    try:
        record = json.loads(cert["canonical_record"])
    except ValueError:
        return ["canonical_record is not valid JSON"]
    if not isinstance(record, dict):
        return ["canonical_record is not a JSON object"]

    problems = []
    if record.get("hash") != cert.get("document_hash"):
        problems.append("document_hash")
    stated = {"hash_algo": "algo", "received_at": "received_at",
              "requester": "requester", "metadata": "metadata"}
    for field, key in stated.items():
        if field in cert and cert[field] != record.get(key):
            problems.append(field)
    return problems


def recompute_root(leaf: bytes, path: list[dict[str, str]]) -> bytes:
    running = leaf
    for step in path:
        sibling = bytes.fromhex(step["hash"])
        running = sha256(sibling + running) if step["position"] == "left" else sha256(running + sibling)
    return running


def main() -> int:
    # A console that cannot print the check marks must not stop the verification.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    parser = argparse.ArgumentParser(description="Verify an LKS Notary certificate")
    parser.add_argument("--certificate", required=True, help="URL or path to the certificate JSON")
    parser.add_argument("--file", help="the document itself, to check it matches")
    parser.add_argument("--rpc", help="LKSCOIN node RPC URL, e.g. http://user:pass@127.0.0.1:3344")
    args = parser.parse_args()

    cert = load_certificate(args.certificate)
    failures = 0

    if args.file:
        with open(args.file, "rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
        if digest == cert["document_hash"]:
            print(f"{OK} the file matches the certificate")
        else:
            print(f"{BAD} the file does NOT match: {digest} != {cert['document_hash']}")
            failures += 1

    mismatches = record_mismatches(cert)
    if mismatches:
        print(f"{BAD} not what the certified record says: {', '.join(mismatches)}")
        failures += 1
    else:
        print(f"{OK} the certificate states what the certified record says")

    leaf = sha256(cert["canonical_record"].encode())
    if leaf.hex() == cert["leaf_hash"]:
        print(f"{OK} leaf recomputed from the canonical record")
    else:
        print(f"{BAD} leaf mismatch: {leaf.hex()} != {cert['leaf_hash']}")
        failures += 1

    merkle = cert.get("merkle")
    on_chain = False
    if not merkle:
        print(f"{INFO} not batched yet: no on-chain proof to check")
    else:
        computed = recompute_root(bytes.fromhex(cert["leaf_hash"]), merkle["path"])
        if computed.hex() == merkle["root"]:
            print(f"{OK} Merkle root recomputed from {len(merkle['path'])} proof steps")
        else:
            print(f"{BAD} root mismatch: {computed.hex()} != {merkle['root']}")
            failures += 1

        chain = cert.get("chain") or {}
        if args.rpc and chain.get("txid"):
            try:
                tx = rpc_call(args.rpc, "getrawtransaction", chain["txid"], 1)
                payloads = [
                    bytes.fromhex(out["scriptPubKey"]["hex"])
                    for out in tx["vout"]
                    if out["scriptPubKey"].get("type") == "nulldata"
                ]
                wanted = MAGIC + bytes([1, 1]) + bytes.fromhex(merkle["root"])
                if any(wanted in script for script in payloads):
                    confirmations = tx.get("confirmations", 0)
                    print(f"{OK} the transaction carries this root on the LKSCOIN chain")
                    print(f"{INFO} confirmations: {confirmations}, "
                          f"block: {tx.get('blockhash', 'unconfirmed')}")
                    on_chain = confirmations > 0
                else:
                    print(f"{BAD} the transaction does not carry this root")
                    failures += 1
            except Exception as exc:
                print(f"{INFO} could not query the node: {exc}")
        elif chain.get("txid"):
            print(f"{INFO} pass --rpc to check txid {chain['txid']} against a node you trust")

    print()
    if failures:
        print(f"INVALID ({failures} failed checks)")
        return EXIT_INVALID
    if not on_chain:
        # Everything checked so far is arithmetic over numbers the certificate itself
        # supplies: anyone can invent a certificate that adds up. Only a node can say
        # that the root was ever published, so without one this is not a VALID.
        print("CONSISTENT, not checked against a node: this does not show the root is "
              "on the chain")
        return EXIT_UNCONFIRMED
    print("VALID")
    return EXIT_VALID


if __name__ == "__main__":
    sys.exit(main())
