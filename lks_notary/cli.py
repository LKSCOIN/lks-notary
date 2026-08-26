"""Administrative commands.

    python -m lks_notary.cli init-db
    python -m lks_notary.cli create-key "Nome cliente"
    python -m lks_notary.cli audit-check
    python -m lks_notary.cli status
"""
from __future__ import annotations

import argparse
import sys

from sqlalchemy import func, select

from . import repository
from .db import engine, session_scope
from .models import Base, Batch, Notarization


def init_db() -> None:
    Base.metadata.create_all(engine)
    print("schema created (or already present)")


def create_key(name: str) -> None:
    with session_scope() as session:
        key_id, secret = repository.create_api_key(session, name)
    print(f"api key id : {key_id}")
    print(f"secret     : {secret}")
    print("\nStore the secret now: only its SHA-256 is kept, it cannot be shown again.")


def audit_check() -> None:
    with session_scope() as session:
        ok, broken = repository.verify_audit_chain(session)
    print("audit chain intact" if ok else f"AUDIT CHAIN BROKEN at entry {broken}")
    sys.exit(0 if ok else 1)


def status() -> None:
    with session_scope() as session:
        by_status = session.execute(
            select(Notarization.status, func.count()).group_by(Notarization.status)
        ).all()
        batches = session.execute(select(func.count()).select_from(Batch)).scalar_one()
        anchored = session.execute(
            select(func.count()).select_from(Batch).where(Batch.ots_upgraded_at.is_not(None))
        ).scalar_one()
    for name, count in by_status:
        print(f"{name:>10}: {count}")
    print(f"{'batches':>10}: {batches} ({anchored} anchored to Bitcoin)")


def main() -> None:
    parser = argparse.ArgumentParser(prog="lks-notary")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-db")
    key = sub.add_parser("create-key")
    key.add_argument("name")
    sub.add_parser("audit-check")
    sub.add_parser("status")
    args = parser.parse_args()

    {"init-db": init_db, "create-key": lambda: create_key(args.name),
     "audit-check": audit_check, "status": status}[args.command]()


if __name__ == "__main__":
    main()
