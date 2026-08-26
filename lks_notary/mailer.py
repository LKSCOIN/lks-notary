"""Outgoing email, over SMTP, standard library only.

Deliberately **not** routed through the website's `lks-mail` service. That
service fixes the recipient in its own configuration on purpose: taking the
recipient from the request body is what made its predecessor an open relay for
four years. Confirmation links have to reach the address the visitor typed, so
reusing it would mean reopening exactly the hole that was just closed.

So the notary talks to the mailbox itself. The credentials live in its own
`.env`, readable only by the service user, and the only messages it can send are
the ones this module composes.
"""
from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

from .config import settings

log = logging.getLogger(__name__)


class MailError(RuntimeError):
    pass


def send(to: str, subject: str, body_html: str, body_text: str) -> None:
    """Send one message. Raises MailError on any failure.

    Both a plain-text and an HTML part are attached: a confirmation link that
    only renders in an HTML client is a link some people cannot use.
    """
    if not settings.smtp_host or not settings.smtp_user:
        raise MailError("SMTP is not configured (SMTP_HOST / SMTP_USER)")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = formataddr((settings.mail_from_name, settings.mail_from))
    message["To"] = to
    message["Message-ID"] = make_msgid(domain=settings.mail_from.split("@")[-1])
    message["Auto-Submitted"] = "auto-generated"
    message.set_content(body_text)
    message.add_alternative(body_html, subtype="html")

    context = ssl.create_default_context()
    try:
        if settings.smtp_port == 465:
            with smtplib.SMTP_SSL(settings.smtp_host, 465, context=context, timeout=30) as smtp:
                smtp.login(settings.smtp_user, settings.smtp_password)
                smtp.send_message(message)
        else:
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=30) as smtp:
                smtp.ehlo()
                smtp.starttls(context=context)
                smtp.login(settings.smtp_user, settings.smtp_password)
                smtp.send_message(message)
    except Exception as exc:  # noqa: BLE001 - every failure is reported the same way
        raise MailError(f"{type(exc).__name__}: {exc}") from exc


def key_confirmation(to: str, confirm_url: str, ttl_hours: int) -> None:
    text = f"""Someone -- we hope you -- requested an API key for LKS Notary,
the notarisation service of the LKS Foundation.

Confirm and get your key:
{confirm_url}

The link works once and expires in {ttl_hours} hours. The key is shown on that
page and nowhere else: we keep only its digest, so we cannot send it to you
again. If you lose it, request another.

If you did not ask for this, ignore this message. No key exists until the link
is opened.

LKS Foundation -- this address is not monitored.
"""
    html = f"""<p>Someone &mdash; we hope you &mdash; requested an API key for
<strong>LKS Notary</strong>, the notarisation service of the LKS Foundation.</p>

<p><a href="{confirm_url}">Confirm and get your key</a></p>

<p>The link works once and expires in {ttl_hours} hours. The key is shown on that
page and nowhere else: we keep only its digest, so we cannot send it to you again.
If you lose it, request another.</p>

<p>If you did not ask for this, ignore this message. No key exists until the link
is opened.</p>

<p style="color:#61758C;font-size:13px">LKS Foundation &mdash; this address is not
monitored.</p>"""
    send(to, "Confirm your LKS Notary API key", html, text)
