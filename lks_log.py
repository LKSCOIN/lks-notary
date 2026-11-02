#!/usr/bin/env python3
"""lks-log -- agent and independent verifier for LKS Log.

Standard library only, single file. Copy it onto the machine whose logs you want
to protect. Log lines never leave that machine: the agent sends the service the
root of a tree built over salted fingerprints, and nothing else.

    export LKS_LOG_API_KEY=...
    lks_log.py init  --state /var/lib/lks-log --name web-1 --source /var/log/auth.log
    lks_log.py run   --state /var/lib/lks-log          # or `seal` from a timer

Checking, which needs no API key:

    lks_log.py verify-period --state /var/lib/lks-log
    lks_log.py prove --state /var/lib/lks-log --text "session opened" -o entry.json
    lks_log.py verify-proof --proof entry.json --rpc http://user:pass@127.0.0.1:3344

The state directory holds what proofs are built from: per-batch secrets and the
position of every sealed line. It holds no log content. Keep it with your logs and
back it up with them: without it the seals stand, but single lines can no longer
be proved. Someone who alters it gains nothing, since its roots are on chain.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

DEFAULT_API = "https://notary.lkschain.io"
API_KEY_ENV = "LKS_LOG_API_KEY"
USER_AGENT = "lks-log/1.0"
ENTRY_TAG = b"LKSLOG1\0"
MAGIC = b"LKSN"
RECORD_VERSION = 1
HEAD_BYTES = 256
MAX_ENTRIES_PER_SEAL = 200_000
GAP_TOLERANCE = 2
OK, BAD, INFO = "[ ok ]", "[FAIL]", "[ -- ]"
EXIT_VALID, EXIT_INVALID, EXIT_INCOMPLETE = 0, 1, 2


class FatalError(Exception):
    """Retrying will not help: a person has to look at this."""


class RetryLater(Exception):
    """The service could not be reached. Whatever was in flight stays queued."""


# --- the seal format, held to lks_notary/log.py by tests/test_log.py ------

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def canonicalize(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                      separators=(",", ":")).encode("utf-8")


def format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def entry_salt(batch_secret: bytes, index: int) -> bytes:
    return hmac.new(batch_secret, index.to_bytes(8, "big"), hashlib.sha256).digest()


def entry_leaf(salt: bytes, line: bytes) -> bytes:
    return sha256(ENTRY_TAG + salt + line)


def canonical_seal(fields: dict[str, Any]) -> bytes:
    record = {
        "v": RECORD_VERSION,
        "stream": fields["stream_id"],
        "sequence": fields["sequence"],
        "interval": fields["interval_seconds"],
        "entry_count": fields["entry_count"],
        "window_start": fields["window_start"],
        "window_end": fields["window_end"],
    }
    if fields.get("entries_root"):
        record["entries_root"] = fields["entries_root"]
    if fields.get("previous_seal"):
        record["previous_seal"] = fields["previous_seal"]
    return canonicalize(record)


def merkle_levels(leaves: list[bytes]) -> list[list[bytes]]:
    """An odd node is promoted, never duplicated: see the notary's README."""
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        current = levels[-1]
        upper = [sha256(current[i] + current[i + 1]) for i in range(0, len(current) - 1, 2)]
        if len(current) % 2 == 1:
            upper.append(current[-1])
        levels.append(upper)
    return levels


def merkle_root(leaves: list[bytes]) -> bytes:
    return merkle_levels(leaves)[-1][0]


def merkle_path(leaves: list[bytes], index: int) -> list[dict[str, str]]:
    path = []
    for level in merkle_levels(leaves)[:-1]:
        if index == len(level) - 1 and len(level) % 2 == 1:
            index //= 2
            continue
        if index % 2 == 0:
            path.append({"hash": level[index + 1].hex(), "position": "right"})
        else:
            path.append({"hash": level[index - 1].hex(), "position": "left"})
        index //= 2
    return path


def recompute_root(leaf: bytes, path: list[dict[str, str]]) -> bytes:
    running = leaf
    for step in path:
        sibling = bytes.fromhex(step["hash"])
        running = sha256(sibling + running) if step["position"] == "left" else sha256(running + sibling)
    return running


# --- talking to the service and to a node ---------------------------------

class Client:
    def __init__(self, api: str, key: str | None = None) -> None:
        self.api = api.rstrip("/")
        self.key = key

    def call(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        # The public service sits behind Cloudflare, which answers 403 to urllib's
        # default User-Agent.
        headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
        if self.key:
            headers["X-API-Key"] = self.key
        request = urllib.request.Request(
            self.api + path, method=method, headers=headers,
            data=json.dumps(body).encode() if body is not None else None,
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:500]
            if exc.code >= 500 or exc.code == 429:
                raise RetryLater(f"HTTP {exc.code}: {detail}") from exc
            raise FatalError(f"{method} {path} refused, HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise RetryLater(f"{self.api}: {exc}") from exc


def split_credentials(url: str) -> tuple[str, dict[str, str]]:
    """urllib does not understand user:pass@ in a URL; node RPC URLs always have it."""
    parts = urlsplit(url)
    headers = {"Content-Type": "application/json"}
    netloc = parts.netloc
    if "@" in netloc:
        credentials, netloc = netloc.rsplit("@", 1)
        headers["Authorization"] = "Basic " + base64.b64encode(credentials.encode()).decode()
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment)), headers


def chain_confirmations(rpc_url: str, txid: str, root_hex: str) -> int | None:
    """Confirmations of a transaction carrying this root; None if it does not carry it."""
    endpoint, headers = split_credentials(rpc_url)
    request = urllib.request.Request(endpoint, headers=headers, data=json.dumps(
        {"jsonrpc": "1.0", "id": "lks-log", "method": "getrawtransaction",
         "params": [txid, 1]}).encode())
    with urllib.request.urlopen(request, timeout=30) as response:
        body = json.load(response)
    if body.get("error"):
        raise RuntimeError(body["error"])
    wanted = MAGIC + bytes([1, 1]) + bytes.fromhex(root_hex)
    carried = any(wanted in bytes.fromhex(out["scriptPubKey"]["hex"])
                  for out in body["result"]["vout"]
                  if out["scriptPubKey"].get("type") == "nulldata")
    return body["result"].get("confirmations", 0) if carried else None


# --- state on disk --------------------------------------------------------

def write_private(path: Path, data: dict[str, Any]) -> None:
    """Atomic, so a crash leaves either the old file or the new one. Private,
    because batch files hold the secrets that salt the fingerprints."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(data, handle, separators=(",", ":"))
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    os.replace(temporary, path)


def read_json(path: Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def batch_file(state_dir: Path, sequence: int) -> Path:
    return state_dir / "batches" / f"{sequence:010d}.json"


# --- reading logs ---------------------------------------------------------

def file_head(handle: Any, length: int) -> str:
    handle.seek(0)
    return sha256(handle.read(length)).hex()


def read_new_lines(
    path: str, position: dict[str, Any] | None, budget: int
) -> tuple[list[tuple[int, bytes]], dict[str, Any]]:
    """Complete lines added since ``position``, and the position after them.

    A line still being written has no terminator yet and waits for the next round:
    sealing half a line would make the finished one impossible to prove.

    Rotation is recognised by the first bytes of the file changing, or by the file
    having shrunk. Lines written to the old file after the last seal and before the
    rotation are not seen; rotate with a postrotate hook running `seal` if that
    window matters.
    """
    with open(path, "rb") as handle:
        size = os.fstat(handle.fileno()).st_size
        offset = 0
        if position:
            same_file = (size >= position["offset"]
                         and file_head(handle, position["head_len"]) == position["head"])
            offset = position["offset"] if same_file else 0
        handle.seek(offset)
        lines: list[tuple[int, bytes]] = []
        while len(lines) < budget:
            raw = handle.readline()
            if not raw.endswith(b"\n"):
                break
            lines.append((offset, raw))
            offset += len(raw)
        head_len = min(HEAD_BYTES, offset)
        return lines, {"offset": offset, "head_len": head_len, "head": file_head(handle, head_len)}


def strip_terminator(raw: bytes) -> bytes:
    return raw[:-2] if raw.endswith(b"\r\n") else raw[:-1] if raw.endswith(b"\n") else raw


# --- the agent ------------------------------------------------------------

def build_pending(state: dict[str, Any]) -> dict[str, Any]:
    secret = secrets.token_bytes(32)
    entries: list[dict[str, Any]] = []
    leaves: list[bytes] = []
    positions = dict(state["files"])
    heads: dict[str, dict[str, Any]] = {}

    for path in state["sources"]:
        budget = MAX_ENTRIES_PER_SEAL - len(entries)
        try:
            lines, positions[path] = read_new_lines(path, state["files"].get(path), budget)
        except OSError as exc:
            # A log that is missing right now may be mid-rotation. Its position is
            # kept, and the verifier will report the lines it cannot find.
            print(f"warning: cannot read {path}: {exc}", file=sys.stderr)
            continue
        heads[path] = {"head": positions[path]["head"], "head_len": positions[path]["head_len"]}
        for offset, raw in lines:
            leaf = entry_leaf(entry_salt(secret, len(leaves)), strip_terminator(raw))
            leaves.append(leaf)
            entries.append({"f": path, "o": offset, "n": len(raw), "leaf": leaf.hex()})

    start = state.get("window_end") or state["created_at"]
    end = format_time(max(datetime.now(timezone.utc), parse_time(start)))
    return {
        "seal": {
            "stream_id": state["stream_id"],
            "sequence": state["sequence"] + 1,
            "interval_seconds": state["interval"],
            "entry_count": len(leaves),
            "window_start": start,
            "window_end": end,
            "entries_root": merkle_root(leaves).hex() if leaves else None,
            "previous_seal": state.get("last_seal"),
        },
        "secret": secret.hex(),
        "heads": heads,
        "entries": entries,
        "positions": positions,
    }


def submit_pending(state_dir: Path, state: dict[str, Any], client: Client,
                   pending: dict[str, Any]) -> dict[str, Any]:
    seal = pending["seal"]
    record = canonical_seal(seal)
    digest = sha256(record).hex()
    answer = client.call("POST", f"/api/v1/log/streams/{seal['stream_id']}/seals", {
        k: seal[k] for k in ("sequence", "entry_count", "window_start", "window_end",
                             "entries_root", "previous_seal")
    })
    # The service builds the record on its own side. If the two differ then the
    # proof on chain is not for the lines we just fingerprinted.
    if answer["seal_hash"] != digest:
        raise FatalError(f"the service computed seal {answer['seal_hash']}, expected {digest}")

    write_private(batch_file(state_dir, seal["sequence"]), {
        "seal": seal, "canonical_record": record.decode(), "seal_hash": digest,
        "certificate_id": answer["certificate_id"], "secret": pending["secret"],
        "heads": pending["heads"], "entries": pending["entries"],
    })
    state.update(sequence=seal["sequence"], last_seal=digest, window_end=seal["window_end"],
                 files=pending["positions"])
    write_private(state_dir / "state.json", state)
    (state_dir / "pending.json").unlink()
    return answer


def seal_once(state_dir: Path, client: Client) -> dict[str, Any]:
    """Seal whatever is new.

    The batch is written to disk before it is sent. If the service cannot be
    reached it stays there and goes first next time, unchanged: no line is skipped,
    and a retry of something already accepted is recognised as the same seal.
    """
    state = read_json(state_dir / "state.json")
    pending_path = state_dir / "pending.json"
    if pending_path.exists():
        submit_pending(state_dir, state, client, read_json(pending_path))
    pending = build_pending(state)
    write_private(pending_path, pending)
    answer = submit_pending(state_dir, state, client, pending)
    print(f"seal {pending['seal']['sequence']}: {pending['seal']['entry_count']} entries, "
          f"proof {answer['verify_url']}", flush=True)
    return answer


def run_forever(state_dir: Path, client: Client) -> int:
    interval = read_json(state_dir / "state.json")["interval"]
    while True:
        try:
            seal_once(state_dir, client)
        except RetryLater as exc:
            print(f"will retry: {exc}", file=sys.stderr, flush=True)
        except FatalError as exc:
            print(f"stopped: {exc}", file=sys.stderr, flush=True)
            return EXIT_INVALID
        time.sleep(interval)


# --- proving one entry ----------------------------------------------------

def read_entry(entry: dict[str, Any], aliases: dict[str, str]) -> bytes:
    with open(aliases.get(entry["f"], entry["f"]), "rb") as handle:
        handle.seek(entry["o"])
        return handle.read(entry["n"])


def find_entry(state_dir: Path, text: str, aliases: dict[str, str]) -> tuple[int, int]:
    needle = text.encode()
    state = read_json(state_dir / "state.json")
    for sequence in range(1, state["sequence"] + 1):
        path = batch_file(state_dir, sequence)
        if not path.exists():
            continue
        for index, entry in enumerate(read_json(path)["entries"]):
            try:
                if needle in read_entry(entry, aliases):
                    return sequence, index
            except OSError:
                continue
    raise FatalError(f"no sealed line contains {text!r} in the files still available")


def build_proof(state_dir: Path, sequence: int, index: int, aliases: dict[str, str],
                client: Client | None) -> dict[str, Any]:
    """A self-contained proof for one line. It discloses that line and a salt that
    opens only that line; the path reveals nothing of the others."""
    batch = read_json(batch_file(state_dir, sequence))
    entries = batch["entries"]
    if not 0 <= index < len(entries):
        raise FatalError(f"seal {sequence} has {len(entries)} entries, no index {index}")
    entry = entries[index]
    line = strip_terminator(read_entry(entry, aliases))
    salt = entry_salt(bytes.fromhex(batch["secret"]), index)
    leaves = [bytes.fromhex(e["leaf"]) for e in entries]
    if entry_leaf(salt, line) != leaves[index]:
        raise FatalError(f"{entry['f']} at offset {entry['o']} no longer holds the sealed line")

    proof: dict[str, Any] = {
        "type": "lks-log-entry-proof",
        "v": RECORD_VERSION,
        "sequence": sequence,
        "source": entry["f"],
        "entry_b64": base64.b64encode(line).decode(),
        "entry_text": line.decode("utf-8", errors="replace"),
        "salt": salt.hex(),
        "path": merkle_path(leaves, index),
        "canonical_record": batch["canonical_record"],
        "seal_hash": batch["seal_hash"],
        "certificate_id": batch["certificate_id"],
        "certificate": None,
    }
    if client is not None:
        try:
            proof["certificate"] = client.call("GET", f"/api/v1/verify/{batch['certificate_id']}")
        except (RetryLater, FatalError) as exc:
            print(f"warning: proof written without its certificate: {exc}", file=sys.stderr)
    return proof


def check_certificate(cert: dict[str, Any], digest: str, rpc: str | None,
                      report: Any, quiet: bool = False) -> bool:
    """From the seal hash to the chain, with the same steps as lks_verify.py.

    Returns whether a node confirmed it. Everything before that step is arithmetic
    over numbers the certificate supplies, and anyone can invent one that adds up.
    """
    def note(text: str) -> None:
        if not quiet:
            print(f"{INFO} {text}")

    record = cert["canonical_record"]
    report(json.loads(record).get("hash") == digest, "the certificate is for this seal")
    leaf = sha256(record.encode())
    report(leaf.hex() == cert["leaf_hash"], "leaf recomputed from the certificate's record")
    merkle = cert.get("merkle")
    if not merkle:
        note("not batched yet: no on-chain proof to check")
        return False
    report(recompute_root(leaf, merkle["path"]).hex() == merkle["root"],
           "batch root recomputed from the inclusion path")
    chain = cert.get("chain") or {}
    if not chain.get("txid"):
        return False
    if not rpc:
        note(f"pass --rpc to check txid {chain['txid']} against a node you trust")
        return False
    try:
        confirmations = chain_confirmations(rpc, chain["txid"], merkle["root"])
    except Exception as exc:
        note(f"could not query the node: {exc}")
        return False
    report(confirmations is not None,
           f"transaction {chain['txid']} carries this root on the LKSCOIN chain")
    note(f"confirmations: {confirmations or 0}")
    return bool(confirmations)


def verify_proof(proof: dict[str, Any], rpc: str | None = None,
                 certificate: dict[str, Any] | None = None) -> int:
    failures = 0

    def report(passed: bool, text: str) -> None:
        nonlocal failures
        print(f"{OK if passed else BAD} {text}")
        failures += 0 if passed else 1

    line = base64.b64decode(proof["entry_b64"])
    record = json.loads(proof["canonical_record"])
    leaf = entry_leaf(bytes.fromhex(proof["salt"]), line)
    report(recompute_root(leaf, proof["path"]).hex() == record.get("entries_root"),
           f"the line belongs to seal {record.get('sequence')}")
    digest = sha256(proof["canonical_record"].encode()).hex()
    report(digest == proof["seal_hash"], "seal hash recomputed from its record")
    certificate = certificate or proof.get("certificate")
    on_chain = False
    if certificate:
        on_chain = check_certificate(certificate, digest, rpc, report)
    else:
        print(f"{INFO} no certificate in this proof: the seal is not tied to the chain")
    print()
    print(f"line: {proof.get('entry_text', '')}")
    if failures:
        print(f"INVALID ({failures} failed checks)")
        return EXIT_INVALID
    if not on_chain:
        print("CONSISTENT, not checked against a node: this does not show the seal is "
              "on the chain")
        return EXIT_INCOMPLETE
    print("VALID")
    return EXIT_VALID


# --- verifying a period ---------------------------------------------------

def check_batch_lines(batch: dict[str, Any], aliases: dict[str, str],
                      tally: dict[str, int], problems: list[str]) -> None:
    """Every sealed line against the log file as it is today.

    If any line of a batch still matches, or the file's first bytes do, this is the
    file that was sealed, and whatever does not match was altered. If nothing
    matches and the first bytes differ, it cannot be told apart from a rotated file:
    those lines count as unchecked and the verdict says so, never as verified.
    Pointing --alias at the rotated copy turns them into a real answer.
    """
    secret = bytes.fromhex(batch["secret"])
    sequence = batch["seal"]["sequence"]
    by_file: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for index, entry in enumerate(batch["entries"]):
        by_file.setdefault(entry["f"], []).append((index, entry))

    for name, entries in by_file.items():
        try:
            handle = open(aliases.get(name, name), "rb")
        except OSError:
            tally["unchecked"] += len(entries)
            continue
        with handle:
            head = batch["heads"][name]
            same_head = file_head(handle, head["head_len"]) == head["head"]
            altered = []
            for index, entry in entries:
                handle.seek(entry["o"])
                line = strip_terminator(handle.read(entry["n"]))
                if entry_leaf(entry_salt(secret, index), line).hex() != entry["leaf"]:
                    altered.append(entry["o"])
        if len(altered) == len(entries) and not same_head:
            tally["unchecked"] += len(entries)
            continue
        tally["verified"] += len(entries) - len(altered)
        tally["altered"] += len(altered)
        problems.extend(f"seal {sequence}: {name} at offset {o} was altered" for o in altered)


def walk_seals(client: Client, stream_id: str, first: int, last: int | None) -> list[dict[str, Any]]:
    seals: list[dict[str, Any]] = []
    after = first - 1
    while True:
        page = client.call("GET", f"/api/v1/log/streams/{stream_id}/seals?after={after}&limit=1000")
        if not page["seals"]:
            return seals
        for seal in page["seals"]:
            if last is not None and seal["sequence"] > last:
                return seals
            seals.append(seal)
        after = page["seals"][-1]["sequence"]


def verify_period(state_dir: Path, client: Client, first: int = 1, last: int | None = None,
                  aliases: dict[str, str] | None = None, certificates: bool = False,
                  rpc: str | None = None) -> int:
    """Logs, local records and published seals against each other."""
    aliases = aliases or {}
    state = read_json(state_dir / "state.json")
    seals = walk_seals(client, state["stream_id"], first, last)
    problems: list[str] = []
    tally = {"verified": 0, "altered": 0, "unchecked": 0}
    missing_batches = 0
    seals_on_chain = 0

    newest = max(state["sequence"], 0) if last is None else last
    published = {s["sequence"] for s in seals}
    for number in range(first, newest + 1):
        if number not in published:
            problems.append(f"seal {number} is recorded locally but missing from the service")

    previous = None
    if first > 1 and batch_file(state_dir, first - 1).exists():
        previous = read_json(batch_file(state_dir, first - 1))["seal_hash"]
    expected = first
    for seal in seals:
        number = seal["sequence"]
        if number != expected:
            problems.append(f"expected seal {expected}, found {number}")
        expected = number + 1
        if sha256(seal["canonical_record"].encode()).hex() != seal["seal_hash"]:
            problems.append(f"seal {number}: hash does not match its record")
        if (number > 1 or previous) and seal["previous_seal"] != previous:
            problems.append(f"seal {number}: does not link to the previous seal")
        previous = seal["seal_hash"]

        path = batch_file(state_dir, number)
        if not path.exists():
            missing_batches += 1
        else:
            batch = read_json(path)
            if batch["seal_hash"] != seal["seal_hash"]:
                problems.append(f"seal {number}: the local record differs from the published seal")
            leaves = [bytes.fromhex(e["leaf"]) for e in batch["entries"]]
            root = merkle_root(leaves).hex() if leaves else None
            if root != json.loads(seal["canonical_record"]).get("entries_root"):
                problems.append(f"seal {number}: the recorded fingerprints do not match its root")
            check_batch_lines(batch, aliases, tally, problems)

        if certificates:
            cert = client.call("GET", f"/api/v1/verify/{seal['proof']['certificate_id']}")

            def report(passed: bool, text: str, number: int = number) -> None:
                if not passed:
                    problems.append(f"seal {number}: {text}: FAILED")

            seals_on_chain += check_certificate(cert, seal["seal_hash"], rpc, report, quiet=True)

    interval = state["interval"]
    gaps = []
    for before, after_seal in zip(seals, seals[1:]):
        seconds = (parse_time(after_seal["received_at"])
                   - parse_time(before["received_at"])).total_seconds()
        if seconds > interval * GAP_TOLERANCE:
            gaps.append((before["sequence"], before["received_at"], after_seal["received_at"]))

    print(f"{INFO} stream {state['stream_id']}, seals {first}-{expected - 1}")
    print(f"{OK if not problems else BAD} seal chain and local records")
    print(f"{INFO} lines verified: {tally['verified']}, altered: {tally['altered']}, "
          f"unchecked: {tally['unchecked']}")
    print(f"{INFO} seals confirmed on a node: {seals_on_chain} of {len(seals)}")
    for before, start, end in gaps:
        print(f"{INFO} gap in sealing after seal {before}: {start} to {end}")
    for problem in problems[:50]:
        print(f"{BAD} {problem}")
    if len(problems) > 50:
        print(f"{BAD} ... and {len(problems) - 50} more")
    print()

    if problems:
        print(f"INVALID ({len(problems)} problems)")
        return EXIT_INVALID
    if tally["unchecked"] or missing_batches:
        print(f"INCOMPLETE: {tally['unchecked']} lines not checked, usually rotated files "
              f"(see --alias); {missing_batches} seals without a local record")
        return EXIT_INCOMPLETE
    if seals_on_chain < len(seals):
        # The lines match the seals, but the seals came from the service. Without a
        # node, a service rewriting its own list would go unnoticed here.
        print(f"CONSISTENT with the seals the service publishes; {len(seals) - seals_on_chain} "
              "not confirmed on a node (see --certificates --rpc)")
        return EXIT_INCOMPLETE
    print("VALID")
    return EXIT_VALID


# --- command line ---------------------------------------------------------

def parse_aliases(values: list[str] | None) -> dict[str, str]:
    aliases = {}
    for value in values or []:
        original, separator, current = value.partition("=")
        if not separator:
            raise FatalError(f"--alias expects ORIGINAL=CURRENT, got {value!r}")
        aliases[original] = current
    return aliases


def command_init(args: argparse.Namespace) -> int:
    state_dir = Path(args.state)
    if (state_dir / "state.json").exists():
        raise FatalError(f"{state_dir} already belongs to a stream")
    key = os.environ.get(API_KEY_ENV)
    if not key:
        raise FatalError(f"set {API_KEY_ENV}: a key on the command line would show up in ps")
    answer = Client(args.api, key).call("POST", "/api/v1/log/streams", {
        "name": args.name, "interval_seconds": args.interval,
    })
    (state_dir / "batches").mkdir(parents=True, exist_ok=True)
    write_private(state_dir / "state.json", {
        "api": args.api, "stream_id": answer["stream_id"], "interval": answer["interval_seconds"],
        "sources": [str(Path(s).resolve()) for s in args.source], "sequence": 0,
        "last_seal": None, "window_end": None,
        "created_at": format_time(datetime.now(timezone.utc)), "files": {},
    })
    print(f"stream {answer['stream_id']}\n{answer['stream_url']}")
    return EXIT_VALID


def stored_client(state_dir: Path, with_key: bool) -> Client:
    key = os.environ.get(API_KEY_ENV) if with_key else None
    if with_key and not key:
        raise FatalError(f"set {API_KEY_ENV}")
    return Client(read_json(state_dir / "state.json")["api"], key)


def main(argv: list[str] | None = None) -> int:
    # A log line in another encoding must not stop the verification on a console
    # that cannot print it.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    parser = argparse.ArgumentParser(description="LKS Log agent and verifier")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="create a stream and a state directory")
    init.add_argument("--state", required=True)
    init.add_argument("--name", required=True, help="a label, readable with the stream id")
    init.add_argument("--source", required=True, action="append", help="log file; repeatable")
    init.add_argument("--interval", type=int, default=300, help="seconds between seals")
    init.add_argument("--api", default=DEFAULT_API)

    for name, text in (("seal", "seal what is new, once"), ("run", "seal at every interval")):
        commands.add_parser(name, help=text).add_argument("--state", required=True)

    prove = commands.add_parser("prove", help="write a proof for one line")
    prove.add_argument("--state", required=True)
    prove.add_argument("--text", help="first sealed line containing this text")
    prove.add_argument("--sequence", type=int)
    prove.add_argument("--index", type=int)
    prove.add_argument("--alias", action="append", metavar="ORIGINAL=CURRENT")
    prove.add_argument("-o", "--output", required=True)

    check = commands.add_parser("verify-proof", help="check a proof, trusting nobody")
    check.add_argument("--proof", required=True)
    check.add_argument("--certificate", help="certificate JSON, if not inside the proof")
    check.add_argument("--rpc", help="LKSCOIN node RPC URL")

    period = commands.add_parser("verify-period", help="check logs against the published seals")
    period.add_argument("--state", required=True)
    period.add_argument("--from", dest="first", type=int, default=1)
    period.add_argument("--to", dest="last", type=int)
    period.add_argument("--alias", action="append", metavar="ORIGINAL=CURRENT",
                        help="where a rotated file is now")
    period.add_argument("--certificates", action="store_true",
                        help="also check every seal's proof; one request per seal")
    period.add_argument("--rpc", help="with --certificates, a LKSCOIN node RPC URL")

    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            return command_init(args)
        if args.command == "verify-proof":
            certificate = read_json(Path(args.certificate)) if args.certificate else None
            return verify_proof(read_json(Path(args.proof)), args.rpc, certificate)

        state_dir = Path(args.state)
        if args.command == "seal":
            seal_once(state_dir, stored_client(state_dir, with_key=True))
            return EXIT_VALID
        if args.command == "run":
            return run_forever(state_dir, stored_client(state_dir, with_key=True))
        if args.command == "prove":
            aliases = parse_aliases(args.alias)
            if args.text:
                sequence, index = find_entry(state_dir, args.text, aliases)
            elif args.sequence is not None and args.index is not None:
                sequence, index = args.sequence, args.index
            else:
                raise FatalError("give --text, or --sequence with --index")
            proof = build_proof(state_dir, sequence, index, aliases,
                                stored_client(state_dir, with_key=False))
            with open(args.output, "w", encoding="utf-8") as handle:
                json.dump(proof, handle, indent=2)
            print(f"proof for seal {sequence}, entry {index}: {args.output}")
            return EXIT_VALID
        return verify_period(state_dir, stored_client(state_dir, with_key=False), args.first,
                             args.last, parse_aliases(args.alias), args.certificates, args.rpc)
    except RetryLater as exc:
        print(f"could not reach the service: {exc}", file=sys.stderr)
        return EXIT_INCOMPLETE
    except FatalError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID


if __name__ == "__main__":
    sys.exit(main())
