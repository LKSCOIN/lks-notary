"""SQLAlchemy models. Mirrors sql/001_schema_mariadb.sql."""
from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
    Date,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    key_hash: Mapped[bytes] = mapped_column(LargeBinary(32), unique=True)
    rate_limit: Mapped[int] = mapped_column(Integer, default=60)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Batch(Base):
    __tablename__ = "batches"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    merkle_root: Mapped[bytes] = mapped_column(LargeBinary(32))
    leaf_count: Mapped[int] = mapped_column(Integer)
    txid: Mapped[bytes | None] = mapped_column(LargeBinary(32), nullable=True)
    block_hash: Mapped[bytes | None] = mapped_column(LargeBinary(32), nullable=True)
    block_height: Mapped[int | None] = mapped_column(Integer, nullable=True)
    confirmations: Mapped[int] = mapped_column(Integer, default=0)
    chainlocked: Mapped[bool] = mapped_column(Boolean, default=False)
    ots_proof: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    ots_upgraded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Notarization(Base):
    __tablename__ = "notarizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    document_hash: Mapped[bytes] = mapped_column(LargeBinary(32))
    hash_algo: Mapped[str] = mapped_column(String(16), default="sha256")
    idempotency_key: Mapped[str | None] = mapped_column(String(128), unique=True, nullable=True)
    requester_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("api_keys.id"), nullable=True
    )
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    leaf_hash: Mapped[bytes] = mapped_column(LargeBinary(32))
    leaf_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    batch_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("batches.id"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(16), default="pending")

    __table_args__ = (
        Index("notarizations_pending_idx", "status", "received_at", "leaf_hash"),
        Index("notarizations_batch_idx", "batch_id", "leaf_index"),
    )


class AnonQuota(Base):
    """Daily counter per anonymous submitter.

    The IP address is never stored: only a salted SHA-256 of it, which is
    enough to count and useless as a log. Rows older than a few days are
    deleted by the worker.
    """

    __tablename__ = "anon_quota"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ip_hash: Mapped[bytes] = mapped_column(LargeBinary(32))
    day: Mapped[date] = mapped_column(Date)
    count: Mapped[int] = mapped_column(Integer, default=0)

    __table_args__ = (UniqueConstraint("ip_hash", "day", name="ip_day"),)


class KeyRequest(Base):
    """A self-service API key request, pending email confirmation.

    The email address is kept: the whole point of this flow is knowing who
    submitted what. The token is stored hashed, like the key itself, so a
    database copy cannot be used to claim a pending request.
    """

    __tablename__ = "key_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(String(254))
    organisation: Mapped[str | None] = mapped_column(String(160), nullable=True)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary(32), unique=True)
    ip_hash: Mapped[bytes | None] = mapped_column(LargeBinary(32), nullable=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    api_key_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("api_keys.id"), nullable=True
    )


class AuditEntry(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    actor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    action: Mapped[str] = mapped_column(String(64))
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    prev_hash: Mapped[bytes | None] = mapped_column(LargeBinary(32), nullable=True)
    entry_hash: Mapped[bytes] = mapped_column(LargeBinary(32))
