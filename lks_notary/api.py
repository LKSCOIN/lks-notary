"""HTTP API and the public verification page."""
from __future__ import annotations

import json
import re
from datetime import datetime
from urllib.parse import quote
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

import logging

from . import __version__, mailer, repository, trace, trace_repo
from .leaf import as_utc, canonical_record
from .config import settings
from .db import get_session
from .merkle import proof, root
from .models import ApiKey, Batch, Notarization

HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
EMAIL = re.compile(r"^[^@\s]+@[^@\s.]+\.[^@\s]+$")
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
log = logging.getLogger(__name__)

app = FastAPI(
    title="LKS Notary",
    version=__version__,
    description="Anchors document hashes to the LKSCOIN blockchain. "
                "Documents never leave the client: only their SHA-256 is sent.",
)


# --- schemas -------------------------------------------------------------

class NotarizeRequest(BaseModel):
    hash: str = Field(description="SHA-256 of the document, hex encoded")
    metadata: dict[str, Any] | None = None

    @field_validator("hash")
    @classmethod
    def _valid_hash(cls, value: str) -> str:
        if not HEX64.match(value):
            raise ValueError("hash must be 64 hex characters (SHA-256)")
        return value.lower()


class KeyRequestBody(BaseModel):
    email: str = Field(description="Where the confirmation link is sent")
    organisation: str | None = Field(default=None, max_length=160)

    @field_validator("email")
    @classmethod
    def _valid_email(cls, value: str) -> str:
        value = value.strip().lower()
        if not EMAIL.match(value) or len(value) > 254:
            raise ValueError("not a valid email address")
        return value


class NotarizeResponse(BaseModel):
    certificate_id: str
    status: str
    received_at: datetime
    leaf_hash: str
    verify_url: str
    created: bool


# --- auth ----------------------------------------------------------------

def optional_api_key(
    session: Session = Depends(get_session),
    x_api_key: str = Header(default=""),
) -> ApiKey | None:
    """An API key when one is presented, None for the anonymous tier.

    A wrong key is still rejected: silently downgrading a mistyped key to
    anonymous would hand the customer a certificate attributed to nobody, and
    they would only notice when they tried to rely on it.
    """
    if not x_api_key:
        return None
    key = repository.api_key_by_secret(session, x_api_key)
    if key is None:
        raise HTTPException(status_code=401, detail="invalid or inactive API key")
    return key


def client_ip(request: Request) -> str:
    """The address nginx says the request came from.

    X-Real-IP is set by our own proxy from $remote_addr, so it cannot be forged
    by the client the way X-Forwarded-For can.
    """
    return request.headers.get("X-Real-IP") or (request.client.host if request.client else "unknown")


# --- routes --------------------------------------------------------------

@app.get("/health")
def health(session: Session = Depends(get_session)) -> dict[str, Any]:
    session.execute(repository.select(Notarization.id).limit(1))
    return {"status": "ok", "version": __version__}


@app.post("/api/v1/notarize", response_model=NotarizeResponse, status_code=202)
def notarize(
    request: NotarizeRequest,
    http_request: Request,
    session: Session = Depends(get_session),
    key: ApiKey | None = Depends(optional_api_key),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> NotarizeResponse:
    """Queue a document hash for the next batch.

    202, not 200: at this point nothing is on chain yet. The hash becomes
    provable when the batch transaction is mined, and independent of LKSCOIN
    when the Bitcoin attestation completes.

    Works with or without an API key. Anonymous submissions are capped per day
    per client address -- not to protect the fee balance, which batching keeps
    flat regardless of volume, but to bound database growth and casual abuse.
    """
    if key is None:
        if not settings.anon_enabled:
            raise HTTPException(status_code=401, detail="an API key is required")
        if not repository.consume_anon_quota(
            session, client_ip(http_request), settings.anon_daily_limit
        ):
            raise HTTPException(
                status_code=429,
                detail=f"anonymous limit of {settings.anon_daily_limit} notarisations per day "
                       "reached; request an API key for unmetered use",
            )

    row, created = repository.create_notarization(
        session, request.hash, key, request.metadata, idempotency_key
    )
    return NotarizeResponse(
        certificate_id=row.id,
        status=row.status,
        received_at=row.received_at,
        leaf_hash=row.leaf_hash.hex(),
        verify_url=f"{settings.public_base_url}/v/{row.id}",
        created=created,
    )


def _certificate(session: Session, row: Notarization) -> dict[str, Any]:
    """Everything a third party needs to check the proof without trusting us."""
    metadata = json.loads(row.metadata_json) if row.metadata_json else None
    requester = row.requester_id or "anonymous"
    received_at = as_utc(row.received_at)
    record = canonical_record(row.document_hash.hex(), received_at, requester, metadata)

    out: dict[str, Any] = {
        "certificate_id": row.id,
        "status": row.status,
        "document_hash": row.document_hash.hex(),
        "hash_algo": row.hash_algo,
        "received_at": received_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "requester": requester,
        "metadata": metadata,
        "canonical_record": record.decode(),
        "leaf_hash": row.leaf_hash.hex(),
        "merkle": None,
        "chain": None,
        "bitcoin": None,
        "spec": {
            "leaf": "SHA-256 of the canonical_record (RFC 8785)",
            "node": "SHA-256(left || right)",
            "odd_leaf": "promoted to the next level, never duplicated (CVE-2012-2459)",
            "payload": "OP_RETURN: 'LKSN' | version 0x01 | type 0x01 | 32-byte root",
        },
    }
    if row.batch_id is None:
        return out

    batch: Batch = session.get(Batch, row.batch_id)
    leaves = repository.batch_leaves(session, batch.id)
    path = proof(leaves, row.leaf_index)
    out["merkle"] = {
        "root": batch.merkle_root.hex(),
        "leaf_index": row.leaf_index,
        "leaf_count": batch.leaf_count,
        "path": [step.to_json() for step in path],
        "recomputed_root": root(leaves).hex(),
    }
    out["chain"] = {
        "network": "LKSCOIN",
        "txid": batch.txid.hex() if batch.txid else None,
        "block_hash": batch.block_hash.hex() if batch.block_hash else None,
        "block_height": batch.block_height,
        "confirmations": batch.confirmations,
        "chainlocked": batch.chainlocked,
    }
    out["bitcoin"] = {
        "anchored": batch.ots_upgraded_at is not None,
        "anchored_at": batch.ots_upgraded_at.isoformat() if batch.ots_upgraded_at else None,
        "ots_available": batch.ots_proof is not None,
        "ots_url": f"/api/v1/batch/{batch.id}/ots" if batch.ots_proof else None,
        "note": "the .ots proof attests SHA-256 of the 32 raw bytes of the Merkle root",
    }
    return out


@app.get("/api/v1/verify/{certificate_id}")
def verify_certificate(
    certificate_id: str, session: Session = Depends(get_session)
) -> dict[str, Any]:
    """Public and unauthenticated on purpose: a proof that only we can check is
    not a proof."""
    row = repository.get_notarization(session, certificate_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown certificate")
    return _certificate(session, row)


@app.get("/api/v1/lookup/{document_hash}")
def lookup(document_hash: str, session: Session = Depends(get_session)) -> dict[str, Any]:
    """Find every certificate issued for a document hash. This is what the
    verification page calls after hashing a file in the browser."""
    if not HEX64.match(document_hash):
        raise HTTPException(status_code=400, detail="hash must be 64 hex characters")
    rows = repository.find_by_document_hash(session, document_hash.lower())
    return {"document_hash": document_hash.lower(),
            "certificates": [_certificate(session, row) for row in rows]}


@app.get("/api/v1/recent")
def recent(limit: int = 50, session: Session = Depends(get_session)) -> dict[str, Any]:
    """Public feed of the latest notarisations.

    Fingerprint, timestamp and chain reference only — see
    repository.recent_notarizations for why the submitter is not included.
    """
    rows = repository.recent_notarizations(session, limit)
    return {
        "totals": repository.totals(session),
        "items": [
            {
                "certificate_id": row[0],
                "document_hash": row[1].hex(),
                "received_at": repository.as_utc(row[2]).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "status": row[3],
                "txid": row[4].hex() if row[4] else None,
                "block_height": row[5],
                "confirmations": row[6] or 0,
                "chainlocked": bool(row[7]),
                "anchored": row[8] is not None,
            }
            for row in rows
        ],
    }


@app.get("/api/v1/batch/{batch_id}/ots")
def batch_ots(batch_id: str, session: Session = Depends(get_session)):
    batch = session.get(Batch, batch_id)
    if batch is None or batch.ots_proof is None:
        raise HTTPException(status_code=404, detail="no OpenTimestamps proof for this batch")
    from fastapi.responses import Response

    return Response(
        content=batch.ots_proof,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{batch_id}.ots"'},
    )


@app.post("/api/v1/request-key", status_code=202)
def request_key(
    body: KeyRequestBody,
    http_request: Request,
    session: Session = Depends(get_session),
) -> dict[str, str]:
    """Ask for an API key. A confirmation link is emailed; no key exists until
    it is opened.

    The response is deliberately identical whether or not the address already
    has a key, and whether or not the mail actually goes out: telling a stranger
    which addresses are registered is an information leak, and telling them
    which ones bounce turns this into an address validator.
    """
    ip = client_ip(http_request)
    if repository.recent_key_requests(session, ip) >= settings.key_requests_per_day:
        raise HTTPException(status_code=429, detail="too many key requests from this address today")

    row, token = repository.create_key_request(session, body.email, body.organisation, ip)
    try:
        mailer.key_confirmation(
            row.email,
            f"{settings.public_base_url}/k/{token}",
            settings.key_request_ttl_hours,
        )
    except mailer.MailError:
        log.exception("could not send the confirmation email for request %s", row.id)

    return {"status": "sent",
            "detail": "If that address can receive mail, a confirmation link is on its way."}


@app.post("/api/v1/confirm-key/{token}")
def confirm_key(token: str, session: Session = Depends(get_session)) -> dict[str, str]:
    """Exchange a confirmation token for the key. Works exactly once."""
    result = repository.confirm_key_request(session, token)
    if result is None:
        raise HTTPException(status_code=410, detail="this link is invalid, already used or expired")
    key_id, secret = result
    return {"api_key_id": key_id, "api_key": secret}


@app.get("/k/{token}")
def confirm_key_page(token: str) -> FileResponse:
    """Page that redeems a confirmation link and shows the key once."""
    return FileResponse(STATIC_DIR / "key.html")


# --- LKS Trace -----------------------------------------------------------

class TraceEventBody(BaseModel):
    lot_id: str = Field(max_length=120, description="Lot identifier, GS1 or free-form")
    event: str = Field(description="One of " + ", ".join(trace.EVENT_TYPES))
    organization: str = Field(max_length=160)
    occurred_at: datetime | None = None
    product_code: str | None = Field(default=None, max_length=64)
    quantity: str | None = Field(default=None, max_length=32,
                                 description="A string, not a number: JCS refuses floats")
    unit: str | None = Field(default=None, max_length=16)
    facility: str | None = Field(default=None, max_length=160)
    parent_lots: list[str] | None = None
    metadata_hash: str | None = Field(default=None,
                                      description="SHA-256 of data you keep in your systems")

    @field_validator("event")
    @classmethod
    def _known_event(cls, value: str) -> str:
        value = value.strip().upper()
        if value not in trace.EVENT_TYPES:
            raise ValueError(f"unknown event type; expected one of {', '.join(trace.EVENT_TYPES)}")
        return value

    @field_validator("metadata_hash")
    @classmethod
    def _valid_metadata_hash(cls, value: str | None) -> str | None:
        if value and not HEX64.match(value):
            raise ValueError("metadata_hash must be 64 hex characters (SHA-256)")
        return value.lower() if value else None


@app.post("/api/v1/trace/lot", status_code=202)
def trace_record(
    body: TraceEventBody,
    http_request: Request,
    session: Session = Depends(get_session),
    key: ApiKey | None = Depends(optional_api_key),
) -> dict[str, Any]:
    """Record one traceability event and queue its proof.

    The event is notarised exactly like a document: only its canonical record
    is hashed and put on chain. Whatever industrial detail you keep in your own
    systems stays there — commit to it with ``metadata_hash`` if you want to be
    able to prove later that it did not change.
    """
    if key is None:
        if not settings.anon_enabled:
            raise HTTPException(status_code=401, detail="an API key is required")
        if not repository.consume_anon_quota(
            session, client_ip(http_request), settings.anon_daily_limit
        ):
            raise HTTPException(status_code=429, detail="daily limit reached for this address")
    try:
        event, notarization = trace_repo.record_event(
            session,
            lot_id=body.lot_id, event_type=body.event, organization=body.organization,
            occurred_at=body.occurred_at, product_code=body.product_code,
            quantity=body.quantity, unit=body.unit, facility=body.facility,
            parent_lots=body.parent_lots, metadata_hash=body.metadata_hash, requester=key,
        )
    except trace.TraceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    parsed = trace.parse_lot_id(body.lot_id)
    return {
        "lot": parsed.to_json(),
        "event_id": event.id,
        "event_hash": event.event_hash.hex(),
        "certificate_id": notarization.id,
        "verify_url": f"{settings.public_base_url}/v/{notarization.id}",
        "lot_url": f"{settings.public_base_url}/lot?id={quote(parsed.raw)}",
        "digital_link": parsed.digital_link(settings.public_base_url),
        "status": "pending",
    }


@app.post("/api/v1/trace/demo", status_code=201)
def trace_demo(
    http_request: Request,
    session: Session = Depends(get_session),
    key: ApiKey | None = Depends(optional_api_key),
) -> dict[str, Any]:
    """Create a sample supply chain: raw material, transformation, a split into
    two lots, a quality check and a shipment. Six real proofs, on the real
    chain — the demo is not a simulation."""
    if key is None and settings.anon_enabled:
        if not repository.consume_anon_quota(
            session, client_ip(http_request), settings.anon_daily_limit
        ):
            raise HTTPException(status_code=429, detail="daily limit reached for this address")
    result = trace_repo.create_demo(session, key)
    result["lot_url"] = f"{settings.public_base_url}/lot?id={quote(result['entry_point'])}"
    return result


@app.get("/api/v1/trace/lot/{lot_id:path}")
def trace_lot(lot_id: str, session: Session = Depends(get_session)) -> dict[str, Any]:
    """Lot state, full chain of custody, and genealogy in both directions.

    Public and unauthenticated, like every read here: a traceability claim that
    only the company can check is a claim, not evidence.
    """
    parsed = trace.parse_lot_id(lot_id)
    lot = trace_repo.get_lot(session, parsed.raw)
    if lot is None:
        raise HTTPException(status_code=404, detail="unknown lot")

    events = trace_repo.lot_events(session, parsed.raw)
    edges = trace_repo.all_edges(session)
    base = settings.public_base_url

    return {
        "lot": {
            **parsed.to_json(),
            "product_code": lot.product_code,
            "organization": lot.organization,
            "status": lot.status,
            "created_at": repository.as_utc(lot.created_at).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "digital_link": parsed.digital_link(base),
        },
        "events": [trace_repo.event_to_json(session, e, base) for e in events],
        "genealogy": {
            "descendants": trace.genealogy(edges, parsed.raw, downstream=True),
            "ancestors": trace.genealogy(edges, parsed.raw, downstream=False),
        },
        "spec": {
            "event_hash": "SHA-256 of canonical_record (JCS, RFC 8785)",
            "chaining": "each event commits to the previous one via previous_hash",
            "proof": "the event hash is notarised; follow verify_url for the Merkle and chain proof",
        },
    }


@app.get("/api/v1/audit/verify")
def audit_verify(session: Session = Depends(get_session)) -> dict[str, Any]:
    ok, broken = repository.verify_audit_chain(session)
    return {"intact": ok, "first_broken_entry": broken}


@app.get("/")
def verification_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "verify.html")


@app.get("/recent")
def recent_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "recent.html")


@app.get("/trace")
def trace_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "trace.html")


@app.get("/lot")
def lot_page() -> FileResponse:
    """Public lot history. The identifier travels in the query string so that a
    GS1 Digital Link, which contains slashes, survives being passed around."""
    return FileResponse(STATIC_DIR / "lot.html")


@app.get("/notarize")
def notarize_page() -> FileResponse:
    """The submission page. Distinct from POST /api/v1/notarize: same word,
    different method and path, so the two never collide."""
    return FileResponse(STATIC_DIR / "notarize.html")


@app.get("/v/{certificate_id}")
def verification_page_for(certificate_id: str) -> FileResponse:
    """Short, shareable URL for one certificate — what goes on a printed
    certificate and inside a QR code. The page reads the id from its own path
    and verifies it in the browser."""
    return FileResponse(STATIC_DIR / "verify.html")


if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
