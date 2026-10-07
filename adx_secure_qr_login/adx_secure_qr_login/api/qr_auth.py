# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""QR login: exchange a scanned credential for a normal Frappe session.

Endpoint contract
-----------------
Every failure path returns HTTP 200 with `{status: "failed"}` and one generic
message. The internal reason code goes to the audit trail and nowhere else. A
caller therefore cannot learn whether a given code ever existed, and cannot
enumerate users by probing.

Two stacked rate limits, because they defend against different things:

* IP-only, long window  -- stops a broad sweep from one host.
* IP + submitted token -- stops hammering one specific credential.

Session creation reuses `LoginManager.login_as()`, exactly as core's own one-time
login link does (`frappe/www/login.py:191`). That yields an ordinary session: the
app never writes a role, a User Permission or any authorization state, so the
user's existing authority is whatever Frappe already computes for them.
"""

import hashlib

import frappe

from adx_secure_qr_login.security import devices, session_guard, validation
from adx_secure_qr_login.secure_qr_login.constants import (
	EVENT_LOGIN_SUCCESS,
	EVENT_RATE_LIMITED,
	EVENT_SECURITY_VALIDATION_FAILED,
	GENERIC_LOGIN_FAILURE_MESSAGE,
	REASON_CONCURRENT_SESSION,
	REASON_LOCKED,
	REASON_OK,
	REASON_RATE_LIMITED,
	REASON_REPLAY_DETECTED,
	REASON_SECURITY_VALIDATION_FAILED,
)
from adx_secure_qr_login.secure_qr_login.doctype.qr_login_audit.qr_login_audit import (
	detect_company,
	log_event,
)
from adx_secure_qr_login.secure_qr_login.doctype.qr_security_settings.qr_security_settings import (
	get_settings,
	is_qr_login_enabled,
)


# --------------------------------------------------------------- rate limits

def _failed(message: str) -> dict:
	"""The one and only shape of a rejection."""
	return {"status": "failed", "message": message}


def _transport_is_secure(settings) -> bool:
	"""Whether this request may carry a QR credential (spec 15).

	Two independent paths to "yes":

	1. `X-Forwarded-Proto: https`, which is what a correctly configured reverse
	    proxy in front of Frappe sends. `frappe.request.scheme` is already
	    rewritten from that header by werkzeug's proxy handling.
	2. A loopback request over plain HTTP. `bench serve` has no certificate, so
	    without this the QR login button cannot be exercised in development at
	    all -- and the alternative would be an insecure default that someone
	    forgets to turn off in production.

	Anything else over plain HTTP is refused. The credential is a bearer token: on
	the wire in cleartext it is equivalent to handing the account over.
	"""
	if not settings.require_https:
		return True

	if not frappe.request:
		# Background/CLI context (scheduler, tests, `bench execute`). There is no
		# network hop here, so the transport rule does not apply.
		return True

	if frappe.request.scheme == "https":
		return True

	return frappe.request.host.startswith(("127.0.0.1", "localhost", "[::1]", "::1"))


def enforce_rate_limits(token: str | None) -> None:
	"""Independent limits, all driven live by QR Security Settings.

	Deliberately implemented here rather than with Frappe's `@rate_limit`
	decorator. That decorator is unsuitable for this endpoint for two reasons:

	1. `seconds` is passed straight to redis `SETEX` (rate_limiter.py:161), so a
	   callable raises `redis.DataError` and a 500. Only `limit` may be a callable,
	   which pins the window length in code and makes it unconfigurable.
	2. Its cache key is built from `frappe.form_dict.cmd` (line 154), which is
	   `None` when the endpoint is reached via `/api/method/<dotted.path>`. Every
	   dotted-path endpoint therefore shares the key `rl:None:<identity>`.

	Neither is a reason to patch core; both are reasons to keep the logic local.

	Three scopes, because they defend against different things and an attacker
	can only be stopped at the scope they cannot trivially change:

	* IP, short window          -- stops a broad sweep from one host
	* IP + submitted token      -- stops hammering one specific credential
	* IP, one hour              -- stops a patient low-and-slow sweep that stays
	                               under the short window all day
	"""
	settings = get_settings()
	limit = settings.rate_limit_attempts or 10
	window = settings.rate_limit_window_seconds or 300
	hourly_limit = settings.ip_rate_limit_per_hour or 30

	ip = getattr(frappe.local, "request_ip", None) or "0.0.0.0"

	# Do not put the raw token in a redis key; it would be readable by anyone with
	# cache access. A short hash of it is enough to separate per-token counters.
	token_key = hashlib.sha256((token or "").encode()).hexdigest()[:16]

	_scoped_rate_limit(f"qr_exchange:ip:{ip}", limit, window)
	if token:
		_scoped_rate_limit(f"qr_exchange:tok:{ip}:{token_key}", limit, window)

	# The hourly scope is checked only when it is meaningfully stricter than the
	# short window, otherwise it would deny a legitimate burst.
	if hourly_limit > limit:
		_scoped_rate_limit(f"qr_exchange:ip_hour:{ip}", hourly_limit, 3600)


def _scoped_rate_limit(key: str, limit: int, window: int) -> None:
	"""Fixed-window counter. Raises RateLimitExceededError past `limit`."""
	redis_key = frappe.cache.make_key(key)
	count = frappe.cache.incrby(redis_key, 1)
	if count == 1:
		# Only set the TTL on creation, otherwise a busy window would keep
		# extending itself and never reset.
		frappe.cache.expire(redis_key, window)
	if count > limit:
		raise frappe.RateLimitExceededError


@frappe.whitelist(allow_guest=True, methods=["POST"])
def qr_exchange(qr_token: str = None, otp: str = None, tmp_id: str = None) -> dict:
	"""Validate a scanned QR credential and sign the user in.

	Two-step when two-factor authentication is required:

	    POST {qr_token}                      -> {status: "otp_required", tmp_id, ...}
	    POST {qr_token, otp, tmp_id}         -> {status: "success", redirect_to}

	No session is created on the first step.
	"""
	settings = get_settings()

	if not is_qr_login_enabled():
		return _failed(frappe._("QR login is not available on this site."))

	if not _transport_is_secure(settings):
		log_event(
			EVENT_SECURITY_VALIDATION_FAILED,
			success=False,
			reason_code="INSECURE_TRANSPORT",
			details={"scheme": frappe.request.scheme if frappe.request else None},
		)
		return _failed(
			frappe._("QR login requires a secure (HTTPS) connection.")
		)

	if not qr_token:
		return _failed(GENERIC_LOGIN_FAILURE_MESSAGE)

	# Rate limiting runs before any database work. A rate-limited caller is
	# rejected with the same generic message as any other failure, so the limit
	# itself is not probeable.
	try:
		enforce_rate_limits(qr_token)
	except frappe.RateLimitExceededError:
		log_event(
			EVENT_RATE_LIMITED,
			success=False,
			reason_code=REASON_RATE_LIMITED,
			details={"scope": "endpoint"},
		)
		return _failed(GENERIC_LOGIN_FAILURE_MESSAGE)

	# ---------------------------------------------------------- validate
	try:
		credential = validation.resolve_credential(qr_token)
	except validation.CredentialRejected as rejected:
		# Two independent counters, deliberately kept separate:
		#
		#   * `note_failure` (redis, short window) throttles one credential fast.
		#   * `_register_credential_failure` (the credential row) is the durable
		#     counter that survives a cache flush and drives the lockout.
		#
		# Only the second one is allowed to move when the credential was actually
		# identified. A token that matches nothing must never increment a counter,
		# or guessing garbage would let anyone lock any employee out on purpose.
		if rejected.credential:
			validation.note_failure(rejected.credential)
			validation.register_credential_failure(rejected.credential)
		log_event(
			rejected.event,
			user=rejected.user,
			credential=rejected.credential,
			success=False,
			reason_code=rejected.reason_code,
			details=rejected.details,
			company=validation.get_user_company(rejected.user) if rejected.user else None,
		)
		return _failed(GENERIC_LOGIN_FAILURE_MESSAGE)

	doc = frappe.get_doc("QR Login Credential", credential)
	user = doc.user

	# ------------------------------------------------------- device policy
	# `device_verification = require_trusted` refuses a device an administrator
	# has revoked. Checked before the 2FA step so no OTP challenge is minted for
	# a device that would be refused anyway. Not counted as a credential failure:
	# the credential is fine, the device is not.
	if not devices.is_trusted_for(user, devices.current_device_id(user)):
		log_event(
			EVENT_SECURITY_VALIDATION_FAILED,
			user=user,
			credential=credential,
			success=False,
			reason_code=REASON_SECURITY_VALIDATION_FAILED,
			details={"reason": "device_revoked"},
			company=validation.get_user_company(user),
		)
		return _failed(GENERIC_LOGIN_FAILURE_MESSAGE)

	# ------------------------------------------------------------- 2FA step
	if settings.require_2fa_on_qr_login:
		from frappe.twofactor import (
			authenticate_for_2factor,
			confirm_otp_token,
			should_run_2fa,
		)

		if should_run_2fa(user):
			if not otp:
				# Step 1: mint the OTP challenge. login_manager.user must be set
				# before confirm_otp_token() is ever reached.
				frappe.local.login_manager.user = user
				authenticate_for_2factor(user)
				return {
					"status": "otp_required",
					"tmp_id": frappe.local.response.get("tmp_id"),
					"verification": frappe.local.response.get("verification"),
					"message": frappe._("Enter the code from your authenticator app."),
				}

			frappe.local.login_manager.user = user
			try:
				confirmed = confirm_otp_token(frappe.local.login_manager, otp=otp, tmp_id=tmp_id)
			except Exception:
				# Expired or unknown tmp_id. Treated as a plain failure so the
				# caller cannot distinguish it from a bad code.
				log_event(
					EVENT_RATE_LIMITED,
					user=user,
					credential=credential,
					success=False,
					reason_code="SECURITY_VALIDATION_FAILED",
					details={"stage": "otp"},
				)
				return _failed(frappe._("That verification code was not accepted. Please try again."))

			if not confirmed:
				validation.note_failure(credential)
				log_event(
					EVENT_RATE_LIMITED,
					user=user,
					credential=credential,
					success=False,
					reason_code="SECURITY_VALIDATION_FAILED",
					details={"stage": "otp_rejected"},
				)
				return _failed(frappe._("That verification code was not accepted. Please try again."))

	# ----------------------------------------------------- create the session
	# Check concurrent session limit before creating a new session.
	if not session_guard.check_concurrent_sessions(user):
		log_event(
			EVENT_RATE_LIMITED,
			user=user,
			credential=credential,
			success=False,
			reason_code=REASON_RATE_LIMITED,
			details={"reason": "concurrent_session_limit"},
		)
		return _failed(GENERIC_LOGIN_FAILURE_MESSAGE)

	# Shared-terminal hygiene: the previous occupant's session is destroyed
	# before the new one exists, not merely overwritten by the cookie.
	if settings.destroy_prior_session:
		session_guard.destroy_prior_session()

	frappe.local.login_manager.login_as(user)
	validation.record_success(credential)
	# Register so `max_concurrent_sessions` counts QR logins only.
	session_guard.register_qr_session(user, frappe.session.sid)

	# Track device if enabled
	if settings.device_tracking:
		_track_device(user, credential)

	log_event(
		EVENT_LOGIN_SUCCESS,
		user=user,
		credential=credential,
		success=True,
		reason_code=REASON_OK,
		details={"generation": doc.generation, "used_2fa": bool(otp)},
		# Hashed, never the sid itself: a raw sid is a resumable bearer token.
		session_reference=session_guard.session_reference(frappe.session.sid),
		company=validation.get_user_company(user) or detect_company(),
	)

	if settings.notify_user_on_use:
		_notify_use(user, doc)

	redirect_to = _redirect_target(user)
	return {"status": "success", "message": frappe._("Signed in."), "redirect_to": redirect_to}


def _redirect_target(user: str) -> str:
	"""Where the browser should land after a successful QR login."""
	from frappe.apps import get_default_path
	from frappe.utils import get_url

	return get_url(get_default_path() or "/desk")


def _notify_use(user: str, doc) -> None:
	"""Email the credential holder that their QR was used. Queued, never inline."""
	try:
		frappe.sendmail(
			recipients=[user],
			subject=frappe._("Your QR login credential was just used"),
			message=frappe._(
				"Your QR login credential ({0}) was used to sign in on {1}. "
				"If this was not you, revoke the credential immediately."
			).format(doc.token_prefix, frappe.utils.now()),
			now=False,
		)
	except Exception:
		frappe.log_error(title="QR use notification failed", message=frappe.get_traceback())


def _track_device(user: str, credential: str) -> None:
	"""Record the device behind this successful QR login.

	Delegates to `security.devices`, which owns device identification and the
	best-effort-write policy. Here it stays a thin call so the authentication
	path has no device logic of its own.
	"""
	devices.track_login(user)


@frappe.whitelist(allow_guest=True, methods=["GET"])
def qr_is_available() -> dict:
	"""Whether to offer the QR option on the login page.

	Deliberately returns nothing about users, credentials or configuration
	detail -- only whether the button should be drawn.
	"""
	try:
		settings = get_settings()
	except Exception:
		# Never let a settings read break the login page for everyone.
		return {"available": False}

	return {
		"available": bool(settings.qr_login_enabled and settings.show_login_option),
	}
