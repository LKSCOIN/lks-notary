"""The independent verifier must agree with the service, byte for byte.

If lks_verify.py and lks_notary/merkle.py ever disagree, every certificate we
issued becomes unverifiable by third parties -- so this is checked in CI.
"""
import hashlib
import importlib.util
import io
import json
import pathlib
import sys
from datetime import datetime, timezone

import pytest
from fake_node import FakeNode

from lks_notary.leaf import canonical_record, leaf_hash
from lks_notary.merkle import proof, root
from lks_notary.payload import batch_root

spec = importlib.util.spec_from_file_location(
    "lks_verify", pathlib.Path(__file__).resolve().parent.parent / "lks_verify.py"
)
lks_verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lks_verify)


class _Closed:
    """Stands in for a server a test has already shut down."""

    def shutdown(self):
        pass

    def server_close(self):
        pass


def leaves(n):
    return [hashlib.sha256(f"leaf-{i}".encode()).digest() for i in range(n)]


def certificate(document, tmp_path, **changes):
    """A genuine certificate for ``document``, as a file, with optional forgeries."""
    digest = hashlib.sha256(document).hexdigest()
    received_at = datetime(2026, 8, 27, 9, 0, 0, tzinfo=timezone.utc)
    metadata = {"ref": "contract-7"}
    record = canonical_record(digest, received_at, "key-1", metadata)
    leaf = leaf_hash(digest, received_at, "key-1", metadata)
    others = leaves(4)[1:]
    tree = [leaf, *others]
    cert = {
        "document_hash": digest,
        "hash_algo": "sha256",
        "received_at": "2026-08-27T09:00:00Z",
        "requester": "key-1",
        "metadata": metadata,
        "canonical_record": record.decode(),
        "leaf_hash": leaf.hex(),
        "merkle": {"root": root(tree).hex(),
                   "path": [step.to_json() for step in proof(tree, 0)]},
        "chain": None,
    }
    cert.update(changes)
    path = tmp_path / "cert.json"
    path.write_text(json.dumps(cert))
    return str(path)


def run_verifier(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["lks-verify", *args])
    return lks_verify.main()


@pytest.fixture
def node():
    fake = FakeNode()
    yield fake
    fake.close()


def published_certificate(document, tmp_path, node):
    """A genuine certificate whose batch root really is in a transaction on the node."""
    path = certificate(document, tmp_path)
    cert = json.loads(pathlib.Path(path).read_text())
    txid = node.send_op_return(batch_root(bytes.fromhex(cert["merkle"]["root"])).hex())
    cert["chain"] = {"txid": txid}
    pathlib.Path(path).write_text(json.dumps(cert))
    return path


def test_a_genuine_certificate_confirmed_on_a_node_is_valid(tmp_path, monkeypatch, capsys, node):
    document = tmp_path / "contract.pdf"
    document.write_bytes(b"the real contract")
    cert = published_certificate(b"the real contract", tmp_path, node)
    assert run_verifier(monkeypatch, "--certificate", cert, "--file", str(document),
                        "--rpc", node.url) == lks_verify.EXIT_VALID
    assert capsys.readouterr().out.strip().endswith("VALID")


def test_without_a_node_a_certificate_is_never_called_valid(tmp_path, monkeypatch, capsys, node):
    cert = published_certificate(b"the real contract", tmp_path, node)
    assert run_verifier(monkeypatch, "--certificate", cert) == lks_verify.EXIT_UNCONFIRMED
    text = capsys.readouterr().out
    assert "CONSISTENT" in text and "VALID" not in text


def test_an_invented_certificate_adds_up_and_is_still_not_valid(tmp_path, monkeypatch, capsys, node):
    # The reason for the distinction: every number here is self-consistent, and no
    # transaction ever carried this root.
    cert = certificate(b"never notarised by anyone", tmp_path, chain={"txid": "ab" * 32})
    assert run_verifier(monkeypatch, "--certificate", cert) == lks_verify.EXIT_UNCONFIRMED
    assert "VALID" not in capsys.readouterr().out


def test_an_invented_certificate_pointing_at_a_real_transaction_fails(tmp_path, monkeypatch, node):
    # A real transaction, carrying somebody else's root.
    txid = node.send_op_return(batch_root(b"\x07" * 32).hex())
    cert = certificate(b"never notarised by anyone", tmp_path, chain={"txid": txid})
    assert run_verifier(monkeypatch, "--certificate", cert,
                        "--rpc", node.url) == lks_verify.EXIT_INVALID


def test_a_transaction_not_yet_in_a_block_is_not_valid(tmp_path, monkeypatch, node):
    cert = published_certificate(b"the real contract", tmp_path, node)
    node.confirmations = 0
    assert run_verifier(monkeypatch, "--certificate", cert,
                        "--rpc", node.url) == lks_verify.EXIT_UNCONFIRMED


def test_a_node_that_cannot_be_reached_is_not_valid(tmp_path, monkeypatch, node):
    cert = published_certificate(b"the real contract", tmp_path, node)
    url = node.url
    node.close()
    assert run_verifier(monkeypatch, "--certificate", cert,
                        "--rpc", url) == lks_verify.EXIT_UNCONFIRMED
    node.server = _Closed()


def test_a_certificate_not_batched_yet_is_not_valid(tmp_path, monkeypatch):
    cert = certificate(b"the real contract", tmp_path, merkle=None)
    assert run_verifier(monkeypatch, "--certificate", cert) == lks_verify.EXIT_UNCONFIRMED


def test_a_certificate_cannot_borrow_the_proof_of_another_document(tmp_path, monkeypatch, capsys):
    # The forgery: a genuine record, leaf and path, belonging to another document,
    # with only the visible document_hash replaced by the hash of the forger's file.
    forged = tmp_path / "forged.pdf"
    forged.write_bytes(b"a contract nobody ever notarised")
    cert = certificate(b"the real contract", tmp_path,
                       document_hash=hashlib.sha256(forged.read_bytes()).hexdigest())
    assert run_verifier(monkeypatch, "--certificate", cert, "--file", str(forged)) == 1
    assert "INVALID" in capsys.readouterr().out


@pytest.mark.parametrize("changes", [
    {"received_at": "2020-01-01T00:00:00Z"},
    {"requester": "somebody-respectable"},
    {"metadata": {"ref": "another-contract"}},
    {"metadata": None},
    {"hash_algo": "md5"},
])
def test_stated_fields_must_match_the_record_that_was_hashed(tmp_path, monkeypatch, changes):
    cert = certificate(b"the real contract", tmp_path, **changes)
    assert run_verifier(monkeypatch, "--certificate", cert) == 1


def test_a_certificate_without_a_valid_record_is_invalid_not_a_crash(tmp_path, monkeypatch):
    cert = certificate(b"the real contract", tmp_path, canonical_record="not json")
    assert run_verifier(monkeypatch, "--certificate", cert) == 1


def test_fetching_a_certificate_identifies_the_tool(monkeypatch):
    # Cloudflare answers 403 to urllib's default User-Agent, which broke every
    # --certificate given as a URL against the public service.
    seen = {}

    class Answer(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    def fake_urlopen(request, timeout=None):
        seen["agent"] = request.get_header("User-agent")
        return Answer(b'{"ok": true}')

    monkeypatch.setattr(lks_verify.urllib.request, "urlopen", fake_urlopen)
    assert lks_verify.load_certificate("https://example.test/cert") == {"ok": True}
    assert seen["agent"].startswith("lks-verify/")


def test_a_console_that_cannot_print_check_marks_does_not_stop_it(tmp_path, monkeypatch):
    raw = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(raw, encoding="cp1252"))
    cert = certificate(b"the real contract", tmp_path)
    assert run_verifier(monkeypatch, "--certificate", cert) == lks_verify.EXIT_UNCONFIRMED


def test_verifier_recomputes_the_same_root_for_every_tree_shape():
    for n in range(1, 20):
        ls = leaves(n)
        expected = root(ls)
        for i in range(n):
            path = [step.to_json() for step in proof(ls, i)]
            assert lks_verify.recompute_root(ls[i], path) == expected, f"n={n} i={i}"


def test_verifier_rejects_a_forged_path():
    ls = leaves(7)
    path = [step.to_json() for step in proof(ls, 2)]
    path[0]["hash"] = hashlib.sha256(b"forged").hexdigest()
    assert lks_verify.recompute_root(ls[2], path) != root(ls)


def test_credentials_move_from_the_url_to_a_header():
    url, headers = lks_verify.split_credentials("http://user:secret@127.0.0.1:3344")
    assert url == "http://127.0.0.1:3344"
    assert headers["Authorization"] == "Basic dXNlcjpzZWNyZXQ="


def test_url_without_credentials_is_untouched():
    url, headers = lks_verify.split_credentials("http://127.0.0.1:3344")
    assert url == "http://127.0.0.1:3344"
    assert "Authorization" not in headers


def test_password_containing_an_at_sign_is_split_on_the_last_one():
    url, _ = lks_verify.split_credentials("http://user:pa@ss@127.0.0.1:3344")
    assert url == "http://127.0.0.1:3344"
