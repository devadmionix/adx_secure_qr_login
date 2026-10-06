# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Credential token generation, hashing and verification.

Design A (bearer credential):

* The token is 256 bits of CSPRNG entropy, rendered URL-safe so it survives
  being embedded in a QR module matrix and re-typed by a human.
* Only `sha256(token)` is persisted. A dump of the database therefore yields
  nothing that can be presented to the login endpoint.
* The plaintext token exists in exactly two places: the response to the generate
  / regenerate call that minted it, and the rendered QR image. It is never
  written to a field, a log line, an audit row or a filename.

The QR payload is a versioned, self-describing string:

    ADXQR1.<token>

The prefix carries no user data and no secret. It exists so the scanner can
reject an unrelated QR code without a database round trip, and so a future
payload format can be introduced without ambiguity.
"""

import hashlib
import hmac
import re
import secrets

import frappe

from adx_secure_qr_login.secure_qr_login.constants import (
	TOKEN_HASH_FIELD,
	TOKEN_PREFIX_LENGTH,
)

# Version tag. Bump the digit if the payload grammar ever changes.
PAYLOAD_VERSION = "ADXQR1"
PAYLOAD_SEPARATOR = "."
QR_PAYLOAD_PREFIX = f"{PAYLOAD_VERSION}{PAYLOAD_SEPARATOR}"

# 32 bytes -> 256 bits -> 43 base64url characters.
TOKEN_BYTES = 32

# Guard rails against a caller stuffing an entire document into the endpoint.
MAX_TOKEN_LENGTH = 256

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,128}$")


def generate_token() -> str:
	"""Return a fresh 256-bit URL-safe bearer token."""
	return secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(token: str) -> str:
	"""Return the stored representation of a token.

	SHA-256 over the raw token. Deliberately *not* a password KDF: the input
	already has 256 bits of entropy, so a slow KDF would add latency to every
	login without meaningfully raising the bar for anyone who already holds the
	hash.
	"""
	assert isinstance(token, str)
	return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_prefix(token: str) -> str:
	"""Non-secret leading characters, safe to display and to log."""
	return (token or "")[:TOKEN_PREFIX_LENGTH]


def build_payload(token: str) -> str:
	"""Wrap a token in the versioned QR payload grammar."""
	return f"{QR_PAYLOAD_PREFIX}{token}"


def parse_payload(raw: str) -> str | None:
	"""Extract the bare token from a scanned payload.

	Accepts the versioned form and, tolerantly, a bare token. Returns None for
	anything that cannot be a token, so callers get a single "invalid" outcome
	rather than having to enumerate failure modes.
	"""
	if not raw or not isinstance(raw, str):
		return None

	candidate = raw.strip()

	# A URL form would put the secret in browser history, proxy logs and
	# Referer headers. This app never mints one, so refuse rather than accept.
	if "://" in candidate or candidate.startswith("/"):
		return None

	if candidate.startswith(QR_PAYLOAD_PREFIX):
		candidate = candidate[len(QR_PAYLOAD_PREFIX) :]
	elif PAYLOAD_VERSION in candidate:
		# Unknown payload version: reject rather than guess at the grammar.
		return None

	if len(candidate) > MAX_TOKEN_LENGTH or not _TOKEN_RE.match(candidate):
		return None

	return candidate


def find_credential_by_token(token: str) -> str | None:
	"""Resolve a token to a credential docname, or None.

	The lookup is by hash only. The credential's docname is never accepted as a
	lookup key, because frappe's `hash` autoname is only partially random
	(timestamp prefix plus seven characters).
	"""
	if not token:
		return None

	digest = hash_token(token)
	rows = frappe.get_all(
		"QR Login Credential",
		filters={TOKEN_HASH_FIELD: digest},
		pluck="name",
		limit=2,
	)
	if not rows:
		return None
	if len(rows) > 1:
		# Two credentials sharing a hash means a minting bug. Refuse to guess.
		frappe.log_error(
			title="QR credential hash collision",
			message=f"{len(rows)} credentials share one token hash",
		)
		return None
	return rows[0]


def hashes_match(expected: str, actual: str) -> bool:
	"""Constant-time hash comparison.

	Not strictly required here, because lookup is by equality in the database
	rather than by comparing a supplied secret to a stored one. Kept so that any
	future "verify against a known hash" path does not introduce a timing oracle.
	"""
	return hmac.compare_digest((expected or "").encode(), (actual or "").encode())
