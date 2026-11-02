"""LKS Log end to end: the real agent against the real API over HTTP.

Only two things are stand-ins: SQLite instead of MariaDB, and a fake node that
accepts the batch transaction. The batcher, the Merkle proofs and the certificates
are the production code, so a verified proof here went through the same steps as
one on mainnet.
"""
import base64
import importlib.util
import json
import pathlib
import socket
import threading
import time

import pytest
import uvicorn
from fake_node import FakeNode
from sqlalchemy import BigInteger, create_engine
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from lks_notary import repository
from lks_notary.api import app
from lks_notary.batcher import publish_batch
from lks_notary.db import get_session
from lks_notary.models import Base

spec = importlib.util.spec_from_file_location(
    "lks_log", pathlib.Path(__file__).resolve().parent.parent / "lks_log.py"
)
lks_log = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lks_log)


@compiles(BigInteger, "sqlite")
def _sqlite_bigint(element, compiler, **kw):
    # SQLite only autoincrements a column declared exactly INTEGER.
    return "INTEGER"


@pytest.fixture(scope="module")
def service():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    def session_override():
        session = factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    app.dependency_overrides[get_session] = session_override

    with factory() as session:
        _, key = repository.create_api_key(session, "Acme SpA")
        _, other_key = repository.create_api_key(session, "Someone Else")
        session.commit()

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.02)

    node = FakeNode()
    yield {"api": f"http://127.0.0.1:{port}", "key": key, "other_key": other_key,
           "factory": factory, "node": node}

    node.close()
    server.should_exit = True
    thread.join(timeout=5)
    app.dependency_overrides.clear()


def publish(service):
    """What the worker's batch cycle does."""
    with service["factory"]() as session:
        leaves = repository.pending_leaves(session, 4096)
        result = publish_batch(leaves, service["node"])
        if result is not None:
            repository.record_batch(session, result.merkle_root, result.txid, result.ordered_ids)
        session.commit()


@pytest.fixture
def agent(service, tmp_path, monkeypatch):
    monkeypatch.setenv(lks_log.API_KEY_ENV, service["key"])
    source = tmp_path / "auth.log"
    source.write_bytes(b"")
    state = tmp_path / "state"
    assert lks_log.main(["init", "--state", str(state), "--name", "web-1", "--source",
                         str(source), "--interval", "300", "--api", service["api"]]) == 0
    client = lks_log.Client(service["api"], service["key"])
    return {"source": source, "state": state, "client": client, "service": service,
            "stream_id": lks_log.read_json(state / "state.json")["stream_id"],
            "tmp": tmp_path}


def write(agent, *lines):
    with open(agent["source"], "ab") as handle:
        for line in lines:
            handle.write(line + b"\n")


def verify(agent, *extra):
    """The full check: whatever is pending gets published, and a node confirms it."""
    publish(agent["service"])
    return lks_log.main(["verify-period", "--state", str(agent["state"]), "--certificates",
                         "--rpc", agent["service"]["node"].url, *extra])


def seal(agent):
    return lks_log.seal_once(agent["state"], agent["client"])


# --- the normal path ------------------------------------------------------

def test_lines_never_reach_the_service(agent, monkeypatch):
    sent = []
    original = lks_log.Client.call

    def spy(self, method, path, body=None):
        sent.append(json.dumps(body))
        return original(self, method, path, body)

    monkeypatch.setattr(lks_log.Client, "call", spy)
    write(agent, b"secret-user logged in from 10.0.0.7")
    seal(agent)
    assert sent and not any(b"secret-user" in s.encode() or "10.0.0.7" in s for s in sent)


def test_unaltered_logs_verify(agent):
    write(agent, b"one", b"two", b"three")
    seal(agent)
    write(agent, b"four")
    seal(agent)
    assert verify(agent) == lks_log.EXIT_VALID


def test_an_empty_interval_still_produces_a_seal(agent):
    seal(agent)
    seal(agent)
    state = lks_log.read_json(agent["state"] / "state.json")
    assert state["sequence"] == 2
    assert verify(agent) == lks_log.EXIT_VALID


# --- tampering: the point of the whole service ----------------------------

def test_an_edited_line_is_detected(agent, capsys):
    write(agent, b"login alice", b"login mallory", b"logout alice")
    seal(agent)
    agent["source"].write_bytes(agent["source"].read_bytes().replace(b"mallory", b"bob    "))
    assert verify(agent) == lks_log.EXIT_INVALID
    assert "was altered" in capsys.readouterr().out


def test_a_deleted_line_is_detected(agent):
    # Long enough that the deleted line lies beyond the bytes used to spot rotation.
    write(agent, *[b"filler line %03d, long enough to push past the file head" % i
                   for i in range(10)])
    write(agent, b"login mallory", b"logout alice")
    seal(agent)
    agent["source"].write_bytes(agent["source"].read_bytes().replace(b"login mallory\n", b""))
    assert verify(agent) == lks_log.EXIT_INVALID


def test_a_replaced_file_is_never_reported_as_valid(agent):
    write(agent, b"login alice", b"login mallory")
    seal(agent)
    agent["source"].write_bytes(b"a completely different story\n")
    assert verify(agent) == lks_log.EXIT_INCOMPLETE


def test_editing_the_local_records_is_detected(agent):
    write(agent, b"one", b"two")
    seal(agent)
    path = lks_log.batch_file(agent["state"], 1)
    batch = lks_log.read_json(path)
    batch["entries"][0]["leaf"] = "00" * 32
    lks_log.write_private(path, batch)
    assert verify(agent) == lks_log.EXIT_INVALID


# --- the service refuses to rewrite history -------------------------------

def post_seal(agent, key, **fields):
    client = lks_log.Client(agent["service"]["api"], key)
    return client.call("POST", f"/api/v1/log/streams/{agent['stream_id']}/seals", fields)


def window():
    return {"window_start": "2026-11-02T09:00:00Z", "window_end": "2026-11-02T09:05:00Z"}


def test_a_sequence_cannot_be_reused_with_other_content(agent):
    write(agent, b"one")
    seal(agent)
    with pytest.raises(lks_log.FatalError, match="409.*different content"):
        post_seal(agent, agent["service"]["key"], sequence=1, entry_count=0, **window())


def test_a_sequence_cannot_be_skipped(agent):
    seal(agent)
    state = lks_log.read_json(agent["state"] / "state.json")
    with pytest.raises(lks_log.FatalError, match="409.*expected_sequence\":2"):
        post_seal(agent, agent["service"]["key"], sequence=3, entry_count=0,
                  previous_seal=state["last_seal"], **window())


def test_a_seal_must_link_to_the_last_one(agent):
    seal(agent)
    with pytest.raises(lks_log.FatalError, match="409"):
        post_seal(agent, agent["service"]["key"], sequence=2, entry_count=0,
                  previous_seal="00" * 32, **window())


def test_another_key_cannot_extend_the_stream(agent):
    with pytest.raises(lks_log.FatalError, match="403"):
        post_seal(agent, agent["service"]["other_key"], sequence=1, entry_count=0, **window())


def test_no_key_cannot_write(agent):
    with pytest.raises(lks_log.FatalError, match="401"):
        post_seal(agent, None, sequence=1, entry_count=0, **window())


# --- a lost connection loses nothing --------------------------------------

def test_a_failed_send_is_retried_unchanged_and_no_line_is_lost(agent, monkeypatch):
    write(agent, b"one")
    original = lks_log.Client.call

    def down(self, method, path, body=None):
        raise lks_log.RetryLater("connection refused")

    monkeypatch.setattr(lks_log.Client, "call", down)
    with pytest.raises(lks_log.RetryLater):
        seal(agent)
    queued = lks_log.read_json(agent["state"] / "pending.json")
    monkeypatch.setattr(lks_log.Client, "call", original)

    write(agent, b"two")
    seal(agent)

    first = lks_log.read_json(lks_log.batch_file(agent["state"], 1))
    assert first["seal"] == queued["seal"]
    second = lks_log.read_json(lks_log.batch_file(agent["state"], 2))
    assert first["seal"]["entry_count"] == 1 and second["seal"]["entry_count"] == 1
    assert verify(agent) == lks_log.EXIT_VALID


def test_a_lost_response_is_recognised_as_the_same_seal(agent, monkeypatch):
    write(agent, b"one")
    original = lks_log.Client.call

    def accepted_then_lost(self, method, path, body=None):
        original(self, method, path, body)
        raise lks_log.RetryLater("connection reset")

    monkeypatch.setattr(lks_log.Client, "call", accepted_then_lost)
    with pytest.raises(lks_log.RetryLater):
        seal(agent)
    monkeypatch.setattr(lks_log.Client, "call", original)

    seal(agent)
    assert lks_log.read_json(agent["state"] / "state.json")["sequence"] == 2
    assert verify(agent) == lks_log.EXIT_VALID


# --- rotation -------------------------------------------------------------

def test_a_rotated_file_is_unchecked_until_pointed_at(agent):
    write(agent, b"before rotation one", b"before rotation two")
    seal(agent)
    rotated = agent["tmp"] / "auth.log.1"
    agent["source"].rename(rotated)
    agent["source"].write_bytes(b"after rotation\n")
    seal(agent)

    assert verify(agent) == lks_log.EXIT_INCOMPLETE
    # An alias applies to the whole run, so each file is checked with its own seals.
    assert verify(agent, "--to", "1", "--alias",
                  f"{agent['source'].resolve()}={rotated}") == lks_log.EXIT_VALID
    assert verify(agent, "--from", "2") == lks_log.EXIT_VALID


# --- a single line, proved to a third party -------------------------------

def test_a_single_line_is_proved_all_the_way_to_the_batch(agent, capsys):
    write(agent, b"login alice", b"login mallory", b"logout alice", b"cron ran")
    seal(agent)
    publish(agent["service"])

    output = agent["tmp"] / "entry.json"
    assert lks_log.main(["prove", "--state", str(agent["state"]), "--text", "mallory",
                         "-o", str(output)]) == 0
    capsys.readouterr()
    assert lks_log.main(["verify-proof", "--proof", str(output), "--rpc",
                         agent["service"]["node"].url]) == lks_log.EXIT_VALID
    text = capsys.readouterr().out
    assert "login mallory" in text and "batch root recomputed" in text
    assert text.strip().endswith("VALID")

    proof = json.loads(output.read_text())
    # It discloses the line asked for, and none of the others.
    assert b"alice" not in output.read_bytes()
    assert base64.b64decode(proof["entry_b64"]) == b"login mallory"


def test_a_proof_for_an_edited_line_fails(agent):
    write(agent, b"login mallory", b"logout alice")
    seal(agent)
    publish(agent["service"])
    output = agent["tmp"] / "entry.json"
    lks_log.main(["prove", "--state", str(agent["state"]), "--text", "mallory", "-o", str(output)])

    proof = json.loads(output.read_text())
    proof["entry_b64"] = base64.b64encode(b"login bob").decode()
    assert lks_log.verify_proof(proof) == lks_log.EXIT_INVALID


def test_a_proof_with_a_certificate_for_another_seal_fails(agent):
    write(agent, b"one")
    seal(agent)
    write(agent, b"two")
    seal(agent)
    publish(agent["service"])
    output = agent["tmp"] / "entry.json"
    lks_log.main(["prove", "--state", str(agent["state"]), "--text", "one", "-o", str(output)])
    proof = json.loads(output.read_text())

    other = lks_log.read_json(lks_log.batch_file(agent["state"], 2))["certificate_id"]
    proof["certificate"] = agent["client"].call("GET", f"/api/v1/verify/{other}")
    assert lks_log.verify_proof(proof) == lks_log.EXIT_INVALID


def test_no_proof_can_be_written_for_a_line_that_changed(agent):
    write(agent, b"login mallory", b"logout alice")
    seal(agent)
    agent["source"].write_bytes(agent["source"].read_bytes().replace(b"mallory", b"bob    "))
    assert lks_log.main(["prove", "--state", str(agent["state"]), "--sequence", "1",
                         "--index", "0", "-o", str(agent["tmp"] / "x.json")]) == lks_log.EXIT_INVALID


# --- only a node can make it VALID -----------------------------------------

def sealed_and_proved(agent):
    write(agent, b"one", b"two")
    seal(agent)
    publish(agent["service"])
    output = agent["tmp"] / "entry.json"
    lks_log.main(["prove", "--state", str(agent["state"]), "--text", "one", "-o", str(output)])
    return json.loads(output.read_text())


def test_a_proof_without_a_node_is_never_called_valid(agent, capsys):
    proof = sealed_and_proved(agent)
    capsys.readouterr()
    assert lks_log.verify_proof(proof) == lks_log.EXIT_INCOMPLETE
    text = capsys.readouterr().out
    assert "CONSISTENT" in text and "VALID" not in text


def test_a_proof_for_a_seal_not_batched_yet_is_not_valid(agent):
    write(agent, b"one")
    seal(agent)
    output = agent["tmp"] / "entry.json"
    lks_log.main(["prove", "--state", str(agent["state"]), "--text", "one", "-o", str(output)])
    proof = json.loads(output.read_text())
    publish(agent["service"])
    assert lks_log.verify_proof(proof, rpc=agent["service"]["node"].url) == lks_log.EXIT_INCOMPLETE


def test_a_proof_whose_transaction_carries_another_root_fails(agent):
    proof = sealed_and_proved(agent)
    node = agent["service"]["node"]
    proof["certificate"]["chain"]["txid"] = node.send_op_return("00" * 38)
    assert lks_log.verify_proof(proof, rpc=node.url) == lks_log.EXIT_INVALID


def test_an_unconfirmed_transaction_is_not_valid(agent):
    proof = sealed_and_proved(agent)
    node = agent["service"]["node"]
    node.confirmations = 0
    try:
        assert lks_log.verify_proof(proof, rpc=node.url) == lks_log.EXIT_INCOMPLETE
    finally:
        node.confirmations = 6


def test_a_period_without_a_node_is_consistent_not_valid(agent, capsys):
    write(agent, b"one", b"two")
    seal(agent)
    publish(agent["service"])
    capsys.readouterr()
    code = lks_log.main(["verify-period", "--state", str(agent["state"])])
    text = capsys.readouterr().out
    assert code == lks_log.EXIT_INCOMPLETE
    assert "CONSISTENT" in text and "VALID" not in text


def test_a_period_with_certificates_but_no_node_is_consistent_not_valid(agent):
    write(agent, b"one", b"two")
    seal(agent)
    publish(agent["service"])
    assert lks_log.main(["verify-period", "--state", str(agent["state"]),
                         "--certificates"]) == lks_log.EXIT_INCOMPLETE


def test_a_period_whose_seals_are_not_on_chain_fails(agent):
    write(agent, b"one", b"two")
    seal(agent)
    publish(agent["service"])
    node = agent["service"]["node"]
    saved = dict(node.transactions)
    for txid in saved:
        node.transactions[txid] = "00" * 38
    try:
        assert lks_log.main(["verify-period", "--state", str(agent["state"]), "--certificates",
                             "--rpc", node.url]) == lks_log.EXIT_INVALID
    finally:
        node.transactions.update(saved)


# --- reading a stream -----------------------------------------------------

def test_the_public_view_reports_the_chain_and_holds_no_lines(agent):
    write(agent, b"confidential line")
    seal(agent)
    seal(agent)
    public = lks_log.Client(agent["service"]["api"])
    view = public.call("GET", f"/api/v1/log/streams/{agent['stream_id']}")
    assert view["seal_count"] == 2 and len(view["seals"]) == 2
    assert view["checks"]["chain_problems"] == []
    assert "confidential" not in json.dumps(view)


def test_an_unknown_stream_is_404(service):
    with pytest.raises(lks_log.FatalError, match="404"):
        lks_log.Client(service["api"]).call("GET", "/api/v1/log/streams/nope")
