# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Credential validation for the QR login path.

Decides *whether a credential may authenticate*. Deliberately knows nothing about
sessions or HTTP; `api/qr_auth.py` owns both.

Failure handling: every rejection raises `CredentialRejected` carrying an internal
reason code and audit event. The caller converts that into one uniform,
non-specific response. Distinguishing "no such code" from "revoked" from
"expired" in the HTTP response would turn the endpoint into a credential
enumeration oracle, so that distinction is preserved only in the audit trail.
"""

import frappe

from adx_secure_qr_login.security import tokens
from adx_secure_qr_login.secure_qr_login.constants import (
	CREDENTIAL_STATUS_ACTIVE,
	CREDENTIAL_STATUS_REVOKED,
	CREDENTIAL_STATUS_SUPERSEDED,
	EVENT_EXPIRED_CREDENTIAL,
	EVENT_INACTIVE_USER,
	EVENT_INVALID_CREDENTIAL,
	EVENT_RATE_LIMITED,
	EVENT_REVOKED_CREDENTIAL,
	EVENT_SECURITY_VALIDATION_FAILED,
	REASON_COMPANY_NOT_ASSIGNED,
	REASON_EXPIRED_CREDENTIAL,
	REASON_INACTIVE_USER,
	REASON_INVALID_CREDENTIAL,
	REASON_RATE_LIMITED,
	REASON_REVOKED_CREDENTIAL,
	REASON_SUPERSEDED_CREDENTIAL,
)

# Failures per credential are counted here in redis, independent of System
# Settings, so the control works even on a site that has not configured
# `allow_consecutive_login_attempts`.
CREDENTIAL_FAILURE_KEY = "qr_fail:{0}"


class CredentialRejected(Exception):
	"""Internal control-flow signal. Never surfaced to the caller verbatim."""

	def __init__(self, reason_code, event, *, user=None, credential=None, details=None):
		self.reason_code = reason_code
		self.event = event
		self.user = user
		self.credential = credential
		self.details = details or {}
		super().__init__(reason_code)


def get_failure_count(credential: str) -> int:
	return frappe.cache.get_value(CREDENTIAL_FAILURE_KEY.format(credential)) or 0


def note_failure(credential: str) -> int:
	"""Record a failed attempt against one credential and return the new count."""
	key = CREDENTIAL_FAILURE_KEY.format(credential)
	count = (frappe.cache.get_value(key) or 0) + 1
	frappe.cache.set_value(key, count, expires_in_sec=6 * 60 * 60)
	return count


def clear_failures(credential: str) -> None:
	frappe.cache.delete_value(CREDENTIAL_FAILURE_KEY.format(credential))


def _max_failures() -> int:
	from adx_secure_qr_login.secure_qr_login.doctype.qr_security_settings.qr_security_settings import (
		get_settings,
	)

	return get_settings().max_failed_attempts_per_credential or 5


def resolve_credential(raw: str) -> str:
	"""Validate the scanned payload and return the credential docname.

	:raises CredentialRejected: on any failure, with the internal reason code.
	"""
	# 1. Shape of the payload. Nothing about the credential is learned here.
	token = tokens.parse_payload(raw)
	if not token:
		raise CredentialRejected(REASON_INVALID_CREDENTIAL, EVENT_INVALID_CREDENTIAL)

	# 2. Existence, by hash. Timing of this lookup is independent of whether the
	#    credential exists, since the hash is computed locally either way.
	name = tokens.find_credential_by_token(token)
	if not name:
		raise CredentialRejected(REASON_INVALID_CREDENTIAL, EVENT_INVALID_CREDENTIAL)

	doc = frappe.get_doc("QR Login Credential", name)

	# 3. Brute-force guard, per credential.
	if get_failure_count(name) >= _max_failures():
		raise CredentialRejected(
			REASON_RATE_LIMITED, EVENT_RATE_LIMITED, credential=name, user=doc.user
		)

	# 4. Status. Each terminal state has its own reason so the audit trail is
	#    actionable, even though the response will not be.
	if doc.status == CREDENTIAL_STATUS_REVOKED:
		raise CredentialRejected(
			REASON_REVOKED_CREDENTIAL, EVENT_REVOKED_CREDENTIAL, credential=name, user=doc.user
		)
	if doc.status == CREDENTIAL_STATUS_SUPERSEDED:
		raise CredentialRejected(
			REASON_SUPERSEDED_CREDENTIAL, EVENT_REVOKED_CREDENTIAL, credential=name, user=doc.user
		)
	if doc.status == "Expired":
		raise CredentialRejected(
			REASON_EXPIRED_CREDENTIAL, EVENT_EXPIRED_CREDENTIAL, credential=name, user=doc.user
		)
	if doc.status != CREDENTIAL_STATUS_ACTIVE:
		# Any unexpected status is treated as untrustworthy rather than allowed.
		raise CredentialRejected(
			REASON_INVALID_CREDENTIAL, EVENT_INVALID_CREDENTIAL, credential=name, user=doc.user
		)

	# 5. Expiry, recomputed server-side on every attempt. A printed card therefore
	#    stops working the day it lapses regardless of the status field, which may
	#    not yet have been flipped by a background job.
	if not doc.is_usable():
		raise CredentialRejected(
			REASON_EXPIRED_CREDENTIAL, EVENT_EXPIRED_CREDENTIAL, credential=name, user=doc.user
		)

	# 6. The account itself. A credential cannot outlive or resurrect its subject.
	user_row = frappe.db.get_value(
		"User", doc.user, ["enabled", "user_type"], as_dict=True
	)
	if not user_row:
		raise CredentialRejected(
			REASON_INACTIVE_USER, EVENT_INACTIVE_USER, credential=name, user=doc.user
		)
	if not user_row.enabled or user_row.user_type != "System User":
		raise CredentialRejected(
			REASON_INACTIVE_USER, EVENT_INACTIVE_USER, credential=name, user=doc.user
		)

	# 7. Explicit company association (multi-company QR login). The credential
	#    identifies WHO the user is; User.company states which company the QR
	#    login is bound to. It grants nothing by itself -- all authorization
	#    still comes from ERPNext roles / User Permissions after the normal
	#    session is created. Resolved live on every attempt so a company change
	#    takes effect on the next login; nothing is cached on the credential.
	validate_user_company(doc.user, name)

	return name


def user_has_company_field() -> bool:
	"""Whether the User.company custom field is installed on this site."""
	try:
		return frappe.get_meta("User").has_field("company")
	except Exception:
		return False


def get_user_company(user: str) -> str | None:
	"""The explicit company bound to a user for QR login, or None.

	Returns None when the field is not installed, empty, or points at a
	Company record that no longer exists / is a group (non-transacting).
	Best-effort read for audit logging; the enforcing twin is
	`validate_user_company` below.
	"""
	if not user or not user_has_company_field():
		return None
	try:
		company = frappe.db.get_value("User", user, "company")
		if not company or not frappe.db.exists("Company", company):
			return None
		if frappe.db.get_value("Company", company, "is_group"):
			return None
		return company
	except Exception:
		return None


def validate_user_company(user: str, credential: str) -> str:
	"""Enforce the User.company gate. Returns the validated company.

	:raises CredentialRejected: with COMPANY_NOT_ASSIGNED when the field is
	    missing (fail-closed only when installed: on a site where the custom
	    field was never synced there is nothing to validate against, so the
	    check is skipped rather than bricking every QR login).
	"""
	if not user_has_company_field():
		return ""

	company = get_user_company(user)
	if not company:
		raise CredentialRejected(
			REASON_COMPANY_NOT_ASSIGNED,
			EVENT_SECURITY_VALIDATION_FAILED,
			credential=credential,
			user=user,
		)
	return company


def record_success(credential: str) -> None:
	"""Update usage counters. Failures here must not affect the login outcome."""
	try:
		doc = frappe.get_doc("QR Login Credential", credential)
		doc.db_set("last_used", frappe.utils.now(), notify=False, commit=False)
		doc.db_set("use_count", (doc.use_count or 0) + 1, notify=False, commit=False)
		# Spec 6.1 last_used_ip. The per-attempt IP always lives on the audit row;
		# this is the convenience summary of the most recent success.
		doc.db_set(
			"last_used_ip",
			getattr(frappe.local, "request_ip", None),
			notify=False,
			commit=False,
		)
		clear_failures(credential)
	except Exception:
		frappe.log_error(title="QR usage counter update failed", message=frappe.get_traceback())
