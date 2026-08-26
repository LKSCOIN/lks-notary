"""The independent verifier must agree with the service, byte for byte.

If lks_verify.py and lks_notary/merkle.py ever disagree, every certificate we
issued becomes unverifiable by third parties -- so this is checked in CI.
"""
import hashlib
import importlib.util
import pathlib

from lks_notary.merkle import proof, root

spec = importlib.util.spec_from_file_location(
    "lks_verify", pathlib.Path(__file__).resolve().parent.parent / "lks_verify.py"
)
lks_verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lks_verify)


def leaves(n):
    return [hashlib.sha256(f"leaf-{i}".encode()).digest() for i in range(n)]


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
