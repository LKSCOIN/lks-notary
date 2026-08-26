"""Minimal JSON-RPC client for a LKSCOIN Core node."""
from __future__ import annotations

from typing import Any

import httpx

from .config import settings


class RpcError(RuntimeError):
    def __init__(self, code: int, message: str):
        super().__init__(f"LKSCOIN RPC error {code}: {message}")
        self.code = code


class LksRpc:
    """Client for a LKSCOIN Core node.

    Wallet calls go to ``/wallet/<name>`` so the notary can share a node with
    the block explorer while keeping its own wallet: two processes selecting
    coins from the same wallet would occasionally pick the same UTXO and
    produce conflicting transactions.
    """

    def __init__(
        self,
        url: str | None = None,
        user: str | None = None,
        password: str | None = None,
        wallet: str | None = None,
    ):
        self._url = (url or settings.rpc_url).rstrip("/")
        self._auth = (user or settings.rpc_user, password or settings.rpc_password)
        self._wallet = wallet if wallet is not None else settings.rpc_wallet
        self._client = httpx.Client(timeout=30.0)

    def _endpoint(self, wallet: bool) -> str:
        if wallet and self._wallet:
            return f"{self._url}/wallet/{self._wallet}"
        return self._url

    def call(self, method: str, *params: Any, wallet: bool = False) -> Any:
        response = self._client.post(
            self._endpoint(wallet),
            auth=self._auth,
            json={"jsonrpc": "1.0", "id": "lks-notary", "method": method, "params": list(params)},
        )
        response.raise_for_status()
        body = response.json()
        if body.get("error"):
            raise RpcError(body["error"].get("code", 0), body["error"].get("message", ""))
        return body["result"]

    # --- the handful of calls the notary actually needs -------------------

    def send_op_return(self, payload_hex: str, fee_rate: float | None = None) -> str:
        """Publish an OP_RETURN output and return the txid.

        The fee rate is always explicit: on a chain whose mempool is usually
        empty, ``fundrawtransaction`` fails with "Fee estimation failed" unless
        the node also sets ``fallbackfee``.
        """
        rate = fee_rate if fee_rate is not None else settings.fee_rate
        raw = self.call("createrawtransaction", [], {"data": payload_hex})
        funded = self.call("fundrawtransaction", raw, {"feeRate": rate}, wallet=True)
        signed = self.call("signrawtransactionwithwallet", funded["hex"], wallet=True)
        if not signed.get("complete"):
            raise RpcError(-1, f"signing incomplete: {signed.get('errors')}")
        return self.call("sendrawtransaction", signed["hex"])

    def tx_status(self, txid: str) -> dict[str, Any]:
        """Confirmations, block and ChainLock state for a published batch.

        Uses the wallet's ``gettransaction`` rather than ``getrawtransaction``
        on purpose: the batch transactions are ours, so the wallet knows them,
        and this way the node does **not** need ``txindex=1``. That matters
        when the notary shares a node with a mining pool or an explorer, where
        enabling txindex would force a reindex and hours of downtime.

        Dash's ``gettransaction`` also reports ``chainlock`` directly, which is
        exactly the finality signal we want to record.
        """
        tx = self.call("gettransaction", txid, wallet=True)
        block_hash = tx.get("blockhash")
        height = None
        if block_hash:
            height = self.call("getblock", block_hash, 1).get("height")
        return {
            "confirmations": tx.get("confirmations", 0),
            "block_hash": block_hash,
            "block_height": height,
            "chainlocked": bool(tx.get("chainlock", False)),
        }
