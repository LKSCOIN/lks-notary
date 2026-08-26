"""Runtime configuration, read once from the environment."""
from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    rpc_url: str = os.getenv("LKS_RPC_URL", "http://127.0.0.1:3344")
    rpc_user: str = os.getenv("LKS_RPC_USER", "")
    rpc_password: str = os.getenv("LKS_RPC_PASSWORD", "")
    wallet_label: str = os.getenv("LKS_WALLET_LABEL", "notary-ops")
    rpc_wallet: str = os.getenv("LKS_RPC_WALLET", "notary")
    public_base_url: str = os.getenv("PUBLIC_BASE_URL", "https://notary.lkschain.io").rstrip("/")

    # Anonymous tier. Batching means a thousand submissions in the same window
    # cost exactly one transaction, so the quota is there to bound database
    # growth and casual abuse -- not to protect the fee balance.
    anon_enabled: bool = os.getenv("ANON_ENABLED", "true").lower() == "true"
    anon_daily_limit: int = int(os.getenv("ANON_DAILY_LIMIT", "20"))
    # Salt for hashing client IPs. Change it and every counter resets, which is
    # also the cheapest way to wipe the table.
    anon_ip_salt: str = os.getenv("ANON_IP_SALT", "")

    # Self-service keys, sent over SMTP. Not through the website's lks-mail
    # service: that one fixes the recipient in its own config to avoid being an
    # open relay, and confirmation links must reach the visitor's address.
    smtp_host: str = os.getenv("SMTP_HOST", "")
    smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
    smtp_user: str = os.getenv("SMTP_USER", "")
    smtp_password: str = os.getenv("SMTP_PASSWORD", "")
    mail_from: str = os.getenv("MAIL_FROM", "noreply@lkschain.io")
    mail_from_name: str = os.getenv("MAIL_FROM_NAME", "LKS Notary")
    key_request_ttl_hours: int = int(os.getenv("KEY_REQUEST_TTL_HOURS", "24"))
    key_requests_per_day: int = int(os.getenv("KEY_REQUESTS_PER_DAY", "5"))
    fee_rate: float = float(os.getenv("LKS_FEE_RATE", "0.0001"))
    database_url: str = os.getenv(
        "DATABASE_URL", "mysql+pymysql://notary:notary@127.0.0.1:3306/lks_notary"
    )
    batch_interval_seconds: int = int(os.getenv("BATCH_INTERVAL_SECONDS", "600"))
    batch_max_leaves: int = int(os.getenv("BATCH_MAX_LEAVES", "4096"))


settings = Settings()
