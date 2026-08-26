"""The chain scanner and the payload encoder must agree.

The scanner is what proves the claim "anyone can find these proofs on chain
without the service". If it silently stopped recognising our own outputs, the
claim would quietly become false.
"""
import importlib.util
import pathlib

from lks_notary.payload import batch_root, single

spec = importlib.util.spec_from_file_location(
    "scan_chain", pathlib.Path(__file__).resolve().parent.parent / "scripts" / "scan_chain.py"
)
scan_chain = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan_chain)

ROOT = bytes(range(32))


def script_hex(payload: bytes) -> str:
    """OP_RETURN + a 38-byte push, exactly how the node stores it."""
    return "6a" + f"{len(payload):02x}" + payload.hex()


def test_scanner_recognises_a_batch_root():
    parsed = scan_chain.parse_payload(script_hex(batch_root(ROOT).encode()))
    assert parsed == (1, 1, ROOT.hex())


def test_scanner_recognises_a_single_notarization():
    parsed = scan_chain.parse_payload(script_hex(single(ROOT).encode()))
    assert parsed == (1, 2, ROOT.hex())


def test_scanner_ignores_foreign_op_return():
    assert scan_chain.parse_payload(script_hex(b"OTHR" + bytes([1, 1]) + ROOT)) is None


def test_scanner_ignores_a_normal_payment_output():
    # p2pkh script
    assert scan_chain.parse_payload("76a914" + "00" * 20 + "88ac") is None


def test_scanner_ignores_the_wrong_length():
    assert scan_chain.parse_payload("6a25" + "4c4b534e01" + ROOT.hex()) is None


def test_scanner_ignores_an_unknown_version():
    payload = b"LKSN" + bytes([9, 1]) + ROOT
    assert scan_chain.parse_payload(script_hex(payload)) is None
