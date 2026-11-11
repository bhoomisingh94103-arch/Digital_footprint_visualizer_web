"""
Digital Footprint Intelligence - Email Existence & Deliverability Verification Service
Strictly adheres to cybersecurity verification principles:
1. Syntax validation (RFC 5321/5322).
2. Domain MX records resolution.
3. SMTP delivery with granular error classification (550 5.1.1, recipient rejection).
4. Never marks an email as existing merely because syntax is valid or domain has MX records.
"""

import smtplib
import socket
import re
from functools import lru_cache
from datetime import datetime, timezone, timedelta
import email_validator
from email_validator import EmailNotValidError, EmailSyntaxError
import dns.resolver
from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers, Timeout
from flask import current_app
from models import db, ApiActivityLog

EMAIL_REGEX = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'


def validate_email_syntax(email: str) -> tuple[bool, str, str]:
    """
    Validate email address syntax using email-validator and RFC rules.
    Returns (is_valid: bool, normalized_email: str, error_message: str).
    """
    if not email or not isinstance(email, str):
        return False, '', "Please provide a valid email address."

    email_clean = email.strip()
    if not email_clean:
        return False, '', "Email address cannot be empty."

    # Basic regex check
    if not re.match(EMAIL_REGEX, email_clean):
        return False, email_clean, "Invalid email syntax. Please provide a standard address format (e.g. user@example.com)."

    try:
        # Validate syntax without DNS deliverability check (handled explicitly next)
        validation = email_validator.validate_email(email_clean, check_deliverability=False)
        normalized = validation.normalized.lower()

        # Additional syntax safeguards: no consecutive dots, valid local part boundaries
        local_part, domain_part = normalized.rsplit('@', 1)
        if '..' in local_part or '..' in domain_part:
            return False, normalized, "Invalid email syntax: consecutive dots are not allowed."
        if local_part.startswith('.') or local_part.endswith('.'):
            return False, normalized, "Invalid email syntax: local part cannot start or end with a dot."

        return True, normalized, ""
    except EmailSyntaxError as e:
        return False, email_clean, f"Invalid email syntax: {str(e)}"
    except EmailNotValidError as e:
        return False, email_clean, f"Invalid email syntax: {str(e)}"
    except Exception:
        return False, email_clean, "Invalid email syntax. Please check the address and try again."


@lru_cache(maxsize=256)
def _resolve_domain_mx_cached(domain: str) -> tuple[bool, tuple, str]:
    """Cached DNS MX resolution to prevent latency spikes and timeouts."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 5.0

        answers = resolver.resolve(domain, 'MX')
        mx_hosts = []
        for rdata in answers:
            host_str = str(rdata.exchange).rstrip('.')
            # RFC 7505 Null MX: an MX record of '.' indicates the domain explicitly does not accept email
            if host_str == '' or host_str == '.':
                return False, (), f"Domain '{domain}' explicitly refuses email delivery (Null MX record configured)."
            mx_hosts.append((rdata.preference, host_str))

        # Sort by priority
        mx_hosts.sort(key=lambda x: x[0])
        clean_hosts = tuple(h[1] for h in mx_hosts)

        if not clean_hosts:
            return False, (), f"Domain '{domain}' has no valid mail exchange (MX) hosts configured."

        return True, clean_hosts, ""

    except NXDOMAIN:
        return False, (), f"The domain '{domain}' does not exist. Please check the email domain and try again."
    except NoAnswer:
        return False, (), f"The domain '{domain}' does not have mail exchange (MX) records configured and cannot receive emails."
    except NoNameservers:
        return False, (), "We couldn't verify whether this email address exists. Please check the address and try again."
    except Timeout:
        return False, (), "We couldn't verify whether this email address exists. Please check the address and try again."
    except Exception:
        return False, (), "We couldn't verify whether this email address exists. Please check the address and try again."


def check_domain_mx(domain_or_email: str) -> tuple[bool, list, str]:
    """
    Query DNS MX records to confirm that the domain has mail exchangers capable of receiving emails.
    IMPORTANT: Having MX records confirms domain routing capability, NOT individual mailbox existence.
    Returns (has_mx: bool, mx_hosts: list, error_message: str).
    """
    if not domain_or_email:
        return False, [], "Missing domain or email address."

    if '@' in domain_or_email:
        domain = domain_or_email.rsplit('@', 1)[1].strip().lower()
    else:
        domain = domain_or_email.strip().lower()

    if not domain or '.' not in domain:
        return False, [], f"Invalid domain '{domain}'. A valid top-level domain is required."

    # Disallow localhost, local network domains for public security scanning
    if domain in ('localhost', 'local', 'test', 'invalid'):
        return False, [], f"Domain '{domain}' is a reserved local test domain and cannot receive public emails."

    has_mx, hosts_tuple, err = _resolve_domain_mx_cached(domain)
    return has_mx, list(hosts_tuple), err


def parse_smtp_rejection(code: int, response_text: str, recipient: str) -> str:
    """
    Parse SMTP server status codes and diagnostics into clear cybersecurity error messages.
    Handles 550, 5.1.1, 551, 553, 554, and recipient rejection.
    """
    text_lower = response_text.lower()

    # 550 5.1.1 / Mailbox does not exist / User unknown
    if (code == 550 or '5.1.1' in response_text or 'does not exist' in text_lower or
            'user unknown' in text_lower or 'recipient rejected' in text_lower or
            'no such user' in text_lower or 'invalid recipient' in text_lower):
        return "The mail server rejected this recipient (550 5.1.1: Mailbox does not exist). Please check the address and try again."

    if code in (551, 552, 553, 554) or '5.1.2' in response_text or '5.1.3' in response_text:
        return f"The mail server rejected recipient '{recipient}' ({code}: {response_text.strip()}). We couldn't verify whether this email address exists. Please check the address and try again."

    return "We couldn't verify whether this email address exists. Please check the address and try again."

