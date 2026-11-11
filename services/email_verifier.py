"""
Digital Footprint Intelligence - Email Existence & Deliverability Verification Service
Rules:
A. Invalid email syntax: Reject with "Please enter a valid email address."
B. Valid email syntax and valid domain: Allow process to continue to OTP delivery stage.
C. Mailbox existence cannot be confirmed: Do NOT automatically reject.
D. SMTP explicitly rejects the recipient: Stop the process and show clear delivery error.
E. OTP successfully delivered and verified: Allow user to proceed with email assessment.
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

# Known major global email providers whose domains are universally valid for email delivery
KNOWN_VALID_MAIL_DOMAINS = {
    'gmail.com', 'googlemail.com', 'yahoo.com', 'ymail.com', 'rocketmail.com',
    'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
    'icloud.com', 'me.com', 'mac.com',
    'proton.me', 'protonmail.com', 'aol.com', 'zoho.com', 'mail.com', 'gmx.com'
}


def validate_email_syntax(email: str) -> tuple[bool, str, str]:
    """
    Validate email address syntax using email-validator and RFC rules.
    Rule A: Reject with "Please enter a valid email address."
    Returns (is_valid: bool, normalized_email: str, error_message: str).
    """
    if not email or not isinstance(email, str):
        return False, '', "Please enter a valid email address."

    email_clean = email.strip()
    if not email_clean:
        return False, '', "Please enter a valid email address."

    # Standard regex check
    if not re.match(EMAIL_REGEX, email_clean):
        return False, email_clean, "Please enter a valid email address."

    try:
        # Validate syntax without DNS deliverability check
        validation = email_validator.validate_email(email_clean, check_deliverability=False)
        normalized = validation.normalized.lower()

        # Additional syntax safeguards: no consecutive dots, valid boundaries
        local_part, domain_part = normalized.rsplit('@', 1)
        if '..' in local_part or '..' in domain_part:
            return False, normalized, "Please enter a valid email address."
        if local_part.startswith('.') or local_part.endswith('.'):
            return False, normalized, "Please enter a valid email address."

        return True, normalized, ""
    except Exception:
        return False, email_clean, "Please enter a valid email address."


@lru_cache(maxsize=256)
def _resolve_domain_mx_cached(domain: str) -> tuple[bool, tuple, str, bool]:
    """
    Cached DNS MX resolution.
    Returns (is_valid: bool, mx_hosts: tuple, error_msg: str, is_definitive_error: bool).
    is_definitive_error=True ONLY for NXDOMAIN or Null MX where domain definitely cannot receive mail.
    """
    try:
        resolver = dns.resolver.Resolver()
        # Ensure fast, robust public DNS resolvers are used to avoid lagging local/VPN nameservers
        resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']
        resolver.timeout = 3.0
        resolver.lifetime = 4.0

        answers = resolver.resolve(domain, 'MX')
        mx_hosts = []
        for rdata in answers:
            host_str = str(rdata.exchange).rstrip('.')
            # RFC 7505 Null MX: an MX record of '.' indicates the domain explicitly refuses email
            if host_str == '' or host_str == '.':
                return False, (), f"Domain '{domain}' explicitly refuses email delivery (Null MX).", True
            mx_hosts.append((rdata.preference, host_str))

        mx_hosts.sort(key=lambda x: x[0])
        clean_hosts = tuple(h[1] for h in mx_hosts)

        if not clean_hosts:
            return False, (), f"Domain '{domain}' has no valid mail exchange (MX) hosts configured.", True

        return True, clean_hosts, "", False

    except NXDOMAIN:
        # Definitive error: domain does not exist in DNS
        return False, (), f"The domain '{domain}' does not exist. Please check the email domain and try again.", True
    except NoAnswer:
        # Definitive error: domain exists but has no MX records
        return False, (), f"The domain '{domain}' does not have mail exchange (MX) records configured and cannot receive emails.", True
    except (NoNameservers, Timeout, Exception) as e:
        # Inconclusive/Timeout: do NOT treat DNS timeout as proof that domain/email does not exist!
        return True, (), "DNS lookup inconclusive; proceeding with verification.", False


def check_domain_mx(domain_or_email: str) -> tuple[bool, list, str, bool]:
    """
    Query domain MX records or identify known email providers.
    Rule B: Valid email syntax and valid domain allows process to continue to OTP delivery stage.
    Returns (is_valid_domain: bool, mx_hosts: list, error_message: str, is_definitive_error: bool).
    """
    if not domain_or_email:
        return False, [], "Please enter a valid email address.", True

    if '@' in domain_or_email:
        domain = domain_or_email.rsplit('@', 1)[1].strip().lower()
    else:
        domain = domain_or_email.strip().lower()

    if not domain or '.' not in domain:
        return False, [], "Please enter a valid email address.", True

    # Disallow reserved local test domains in production
    if domain in ('localhost', 'local', 'test', 'invalid'):
        return False, [], f"Domain '{domain}' is a reserved local test domain and cannot receive public emails.", True

    # Major known email providers are universally valid
    if domain in KNOWN_VALID_MAIL_DOMAINS:
        return True, [f"mail.{domain}"], "", False

    # Check DNS for other domains
    is_valid, hosts_tuple, err, is_definitive = _resolve_domain_mx_cached(domain)
    return is_valid, list(hosts_tuple), err, is_definitive


def parse_smtp_rejection(code: int, response_text: str, recipient: str) -> tuple[str, bool]:
    """
    Parse SMTP server status codes and diagnostics into clear cybersecurity error messages.
    Returns (error_message: str, is_explicit_rejection: bool).
    Rule D: SMTP explicitly rejects recipient -> Stop process and show clear delivery error.
    """
    text_lower = response_text.lower()

    # 550 5.1.1 / Mailbox does not exist / User unknown / Recipient rejected
    if (code == 550 or '5.1.1' in response_text or 'does not exist' in text_lower or
            'user unknown' in text_lower or 'recipient rejected' in text_lower or
            'no such user' in text_lower or 'invalid recipient' in text_lower or
            'mailbox unavailable' in text_lower):
        return "The mail server rejected this recipient (550 5.1.1: Mailbox does not exist). Please check the address and try again.", True

    if code in (551, 552, 553, 554) or '5.1.2' in response_text or '5.1.3' in response_text:
        return f"The mail server rejected recipient '{recipient}' ({code}: {response_text.strip()}).", True

    return "Mailbox existence cannot be confirmed upfront; proceeding to verification.", False
