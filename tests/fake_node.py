"""A LKSCOIN node as far as the verifiers can tell: JSON-RPC over HTTP.

Real HTTP so that credentials in the URL, headers and the parsing of the answer are
all exercised. It also accepts the batcher's transaction, so a proof can travel the
whole way from a seal to the node a verifier asks.
"""
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeNode:
    def __init__(self) -> None:
        self.transactions: dict[str, str] = {}
        self.confirmations = 6
        node = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                answer = node.answer(body["method"], body["params"])
                data = json.dumps(answer).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://user:secret@127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def send_op_return(self, payload_hex: str, fee_rate: float | None = None) -> str:
        txid = hashlib.sha256(f"{len(self.transactions)}:{payload_hex}".encode()).hexdigest()
        self.transactions[txid] = payload_hex
        return txid

    def answer(self, method: str, params: list) -> dict:
        payload = self.transactions.get(params[0]) if method == "getrawtransaction" else None
        if payload is None:
            return {"result": None, "error": {"code": -5, "message": "No such transaction"}}
        return {"error": None, "result": {
            "confirmations": self.confirmations,
            "blockhash": "bb" * 32,
            "vout": [
                {"scriptPubKey": {"type": "pubkeyhash", "hex": "76a914"}},
                {"scriptPubKey": {"type": "nulldata", "hex": "6a26" + payload}},
            ],
        }}
