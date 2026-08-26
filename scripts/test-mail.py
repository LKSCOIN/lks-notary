#!/usr/bin/env python3
"""Send one test message, straight through the mailer.

Isolates the mail configuration from everything else: if this works and the key
request still does not, the problem is not SMTP.

    cd /opt/lks-notary && .venv/bin/python scripts/test-mail.py you@example.com
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lks_notary import mailer                      # noqa: E402
from lks_notary.config import settings             # noqa: E402

if len(sys.argv) != 2:
    sys.exit("usage: test-mail.py <recipient>")

print(f"host   : {settings.smtp_host}:{settings.smtp_port}")
print(f"user   : {settings.smtp_user}")
print(f"from   : {settings.mail_from}")
print(f"to     : {sys.argv[1]}")
try:
    mailer.key_confirmation(sys.argv[1], settings.public_base_url + "/k/test-token", 24)
except mailer.MailError as exc:
    sys.exit(f"FAILED: {exc}")
print("sent — check the mailbox, and the spam folder")
