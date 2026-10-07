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
from adx_secure_qr_login.security.dates import is_future, seconds_since
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
	REASON_LOCKED,
	REASON_RATE_LIMITED,
	REASON_REVOKED_CREDENTIAL,
	REASON_REPLAY_DETECTED,
	REASON_SUPERSEDED_CREDENTIAL,
)

# Failures per credential are counted here in redis, independent of System
# Settings, so the control works even on a site that has not configured
# `allow_consecutive_login_attempts`.
CREDENTIAL_FAILURE_KEY = "qr_fail:{0}"

# Grace period for double-submit (mobile prefetch + actual load)
REPLAY_GRACE_SECONDS = 5


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


def _lockout_minutes() -> int:
	from adx_secure_qr_login.secure_qr_login.doctype.qr_security_settings.qr_security_settings import (
		get_settings,
	)

	return get_settings().lockout_minutes or 15


def _replay_policy() -> str:
	from adx_secure_qr_login.secure_qr_login.doctype.qr_security_settings.qr_security_settings import (
		get_settings,
	)

	return get_settings().replay_policy or "single_use"


def _replay_window_seconds() -> int:
	from adx_secure_qr_login.secure_qr_login.doctype.qr_security_settings.qr_security_settings import (
		get_settings,
	)

	return get_settings().replay_window_seconds or 60


def _is_user_qr_enabled(user: str) -> bool:
	"""Check if QR login is enabled for this specific user.

	Returns True if the user has the qr_login_enabled field set to 1 (or if the
	field doesn't exist, for backward compatibility).
	"""
	try:
		enabled = frappe.db.get_value("User", user, "qr_login_enabled")
		# If field doesn't exist or is None, default to enabled
		if enabled is None:
			return True
		return bool(enabled)
	except Exception:
		return True


def _check_lockout(doc) -> None:
	"""Check if the credential is currently locked out.

	:raises CredentialRejected: if the credential is locked.
	"""
	# `is_future` normalises the value: `locked_until` arrives as a string on some
	# load paths and as a datetime on others.
	if is_future(doc.locked_until):
		raise CredentialRejected(
			REASON_LOCKED,
			EVENT_RATE_LIMITED,
			credential=doc.name,
			user=doc.user,
			details={"locked_until": str(doc.locked_until)},
		)


def _register_credential_failure(doc) -> None:
	"""Increment `failed_attempts` and lock the credential at the threshold.

	The counter is re-read from the database rather than taken from `doc`:
	callers hold a document instance whose attribute is a snapshot from when it
	was loaded, so two failures in one request would both compute the same
	"next" value and only one would be persisted. The database is the single
	authoritative count.

	No commit here. This runs on the authentication path, inside the caller's
	transaction; forcing a commit would detach the failure counter from the
	audit row written moments later and would break the caller's rollback on a
	subsequent failure. `api/qr_auth.py` writes the audit event and lets the
	normal request lifecycle commit both together.

	An already-locked credential is not re-locked: the lockout window is fixed
	at the moment the threshold is crossed. Otherwise repeatedly presenting a
	locked credential would push `locked_until` forward indefinitely, which is
	a denial-of-service an attacker could aim at any user who has been
	brute-forced once.
	"""
	if not doc or not doc.get("name"):
		return
	name = doc.get("name")

	try:
		current = (
			frappe.db.get_value(
				"QR Login Credential", name, ["failed_attempts", "locked_until"],
				as_dict=True,
			)
			or {}
		)
		attempts = (current.get("failed_attempts") or 0) + 1

		values = {"failed_attempts": attempts}
		if attempts >= _max_failures() and not current.get("locked_until"):
			values["locked_until"] = frappe.utils.add_to_date(
				frappe.utils.now(), minutes=_lockout_minutes()
			)

		frappe.db.set_value("QR Login Credential", name, values, update_modified=False)
	except Exception:
		# A lost counter must not turn a rejected login into a server error,
		# but it does weaken lockout, so it has to be visible.
		frappe.log_error(
			title="QR credential lockout update failed",
			message=frappe.get_traceback(),
		)


def register_credential_failure(credential) -> None:
	"""Record one failed authentication attempt against `credential`.

	Accepts a docname or a document. Public entry point so the authentication
	path does not have to reach into the private implementation.
	"""
	name = credential if isinstance(credential, str) else (credential or {}).get("name")
	if not name:
		return
	try:
		_register_credential_failure({"name": name})
	except Exception:
		frappe.log_error(
			title="QR credential failure accounting failed",
			message=frappe.get_traceback(),
		)


def clear_credential_failures(doc_or_name) -> None:
	"""Reset the lockout state after a successful authentication."""
	name = doc_or_name if isinstance(doc_or_name, str) else doc_or_name.get("name")
	if not name:
		return
	try:
		frappe.db.set_value(
			"QR Login Credential",
			name,
			{"failed_attempts": 0, "locked_until": None},
			update_modified=False,
		)
	except Exception:
		frappe.log_error(
			title="QR credential lockout reset failed",
			message=frappe.get_traceback(),
		)


def _check_replay(doc) -> None:
	"""Check replay protection policy.

	:raises CredentialRejected: if the credential has already been used.
	"""
	policy = _replay_policy()
	if policy == "disabled":
		return

	elapsed = seconds_since(doc.last_used)
	if elapsed is None:
		# Never used yet: nothing to replay.
		return

	if policy == "single_use":
		# A short grace window absorbs the mobile double-request (link preview
		# prefetch followed by the real page load), which is the same login
		# attempt twice, not a replay.
		if elapsed <= REPLAY_GRACE_SECONDS:
			return
		raise CredentialRejected(
			REASON_REPLAY_DETECTED,
			EVENT_INVALID_CREDENTIAL,
			credential=doc.name,
			user=doc.user,
			details={"reason": "replay_detected", "elapsed_seconds": int(elapsed)},
		)

	if policy == "window":
		if elapsed <= _replay_window_seconds():
			return
		raise CredentialRejected(
			REASON_REPLAY_DETECTED,
			EVENT_INVALID_CREDENTIAL,
			credential=doc.name,
			user=doc.user,
			details={"reason": "replay_detected", "elapsed_seconds": int(elapsed)},
		)


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

	# 5. Lockout, before the expiry check. `is_usable()` also folds in the lockout,
	#    so testing it first would report a locked credential as EXPIRED and the
	#    audit trail would misstate why the attempt failed.
	_check_lockout(doc)

	# 6. Expiry, recomputed server-side on every attempt. A printed card therefore
	#    stops working the day it lapses regardless of the status field, which may
	#    not yet have been flipped by a background job.
	if not doc.is_usable():
		raise CredentialRejected(
			REASON_EXPIRED_CREDENTIAL, EVENT_EXPIRED_CREDENTIAL, credential=name, user=doc.user
		)

	# 7. The account itself. A credential cannot outlive or resurrect its subject.
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

	# 8. Per-user QR login control: the account owner can switch their own QR
	#    access off without an administrator revoking the credential.
	if not _is_user_qr_enabled(doc.user):
		raise CredentialRejected(
			REASON_INACTIVE_USER, EVENT_INACTIVE_USER, credential=name, user=doc.user
		)

	# 9. Explicit company association (multi-company QR login). The credential
	#    identifies WHO the user is; User.company states which company the QR
	#    login is bound to. It grants nothing by itself -- all authorization
	#    still comes from ERPNext roles / User Permissions after the normal
	#    session is created. Resolved live on every attempt so a company change
	#    takes effect on the next login; nothing is cached on the credential.
	validate_user_company(doc.user, name)

	# 10. Replay protection. Check if the credential has already been used.
	_check_replay(doc)

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
		# A correct credential is proof the holder is not guessing, so the durable
		# lockout counter resets too. Without this an employee who mistyped once
		# during a brute-force wave stays one attempt from a lockout forever.
		clear_credential_failures(credential)
	except Exception:
		frappe.log_error(title="QR usage counter update failed", message=frappe.get_traceback())
