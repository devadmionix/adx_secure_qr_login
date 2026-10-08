# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Self-service login QR: type email on the login page, scan the shown code.

Flow (mirrors the reference UX, hardened to this app's security model):

    POST request_login_qr {email}  -> {svg, expires_in}   (guest)
    phone scans code -> GET consume_login_qr?key=...       (guest)
    -> normal Frappe session + redirect to desk

Security properties (deliberately stricter than a naive email-to-QR pipe):

* The endpoint never reveals whether an email exists, is disabled, or lacks
  a company: every refusal returns the same generic message.
* Codes live only in the cache (never in the database), expire after
  5 minutes, and are single-use (10s grace for mobile double-requests).
* Generation is rate-limited per IP and per email.
* HTTPS is honoured per QR Security Settings, like the main QR endpoint.
* Disabled accounts, non-System Users and company-less users are rejected
  at *generation* time, so a code is never minted that could not log in.
* Consumption re-validates the account and creates a *normal* Frappe
  session, so all existing roles / User Permissions apply unchanged.
* Every generation and consumption is audit-logged (no secrets in the log).
"""

import hashlib
import socket
from urllib.parse import urlparse, urlunparse

import frappe

from adx_secure_qr_login.security import qr_image, session_guard
from adx_secure_qr_login.secure_qr_login.constants import (
	EVENT_GENERATED,
	EVENT_INVALID_CREDENTIAL,
	EVENT_LOGIN_SUCCESS,
	REASON_INVALID_CREDENTIAL,
	REASON_OK,
)
from adx_secure_qr_login.secure_qr_login.doctype.qr_login_audit.qr_login_audit import (
	detect_company,
	log_event,
)
from adx_secure_qr_login.secure_qr_login.doctype.qr_security_settings.qr_security_settings import (
	get_settings,
)

EXPIRY_SECONDS = 5 * 60
GENERATE_IP_LIMIT = 10
GENERATE_IP_WINDOW = 60 * 60
GENERATE_EMAIL_LIMIT = 5
GENERATE_EMAIL_WINDOW = 60 * 60
CONSUME_GRACE_SECONDS = 10

# A function, not a module-level constant: `frappe._()` resolves against the
# current site and language, so a literal would freeze the translation of
# whichever site first imported this module.
def generic_generate_failure() -> str:
	"""Uniform failure message for every self-service generation error."""
	return frappe._("Unable to generate QR code. Please check your email address.")


def _cache_key(key: str) -> str:
	"""Cache slot for a code. The raw key never appears in a key name."""
	digest = hashlib.sha256(key.encode()).hexdigest()[:16]
	return f"qr_selfsvc:{digest}"


def _hit_limit(key: str, limit: int, window: int) -> bool:
	redis_key = frappe.cache.make_key(key)
	count = frappe.cache.incrby(redis_key, 1)
	if count == 1:
		frappe.cache.expire(redis_key, window)
	return count > limit


def _request_ip() -> str:
	return getattr(frappe.local, "request_ip", None) or "0.0.0.0"


def _transport_is_secure(settings) -> bool:
	if not settings.require_https:
		return True
	if not frappe.request:
		return True
	if frappe.request.scheme == "https":
		return True
	return frappe.request.host.startswith(("127.0.0.1", "localhost", "[::1]", "::1"))


def _resolve_account(email: str) -> str | None:
	"""Return the user if it may receive a self-service QR, else None.

	One generic outcome for every failure: unknown address, disabled
	account, non-desk account, or missing company association.
	"""
	from adx_secure_qr_login.security import validation

	if not email or not frappe.db.exists("User", email):
		return None
	row = frappe.db.get_value(
		"User", email, ["enabled", "user_type"], as_dict=True
	)
	if not row or not row.enabled or row.user_type != "System User":
		return None
	if not validation.get_user_company(email):
		return None
	return email


def _login_url(key: str) -> str:
	path = f"/api/method/adx_secure_qr_login.api.qr_self_service.consume_login_qr?key={key}"
	if not frappe.request:
		from frappe.utils import get_url

		return f"{get_url()}{path}"
	request_host = frappe.request.host
	scheme = frappe.request.scheme
	url = f"{scheme}://{request_host}{path}"

	# A phone that scans this screen is usually on the same Wi-Fi but cannot
	# resolve `.local`/loopback names, so point it at the server's LAN IP.
	parsed = urlparse(url)
	hostname = parsed.hostname or ""
	if hostname.endswith(".local") or hostname in ("127.0.0.1", "localhost"):
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			s.connect(("8.8.8.8", 80))
			lan_ip = s.getsockname()[0]
			s.close()
			url = urlunparse(
				parsed._replace(
					netloc=f"{lan_ip}:{parsed.port}" if parsed.port else lan_ip
				)
			)
		except Exception:
			pass
	return url


@frappe.whitelist(allow_guest=True, methods=["POST"])
def request_login_qr(email: str = None) -> dict:
	"""Mint a 5-minute, single-use login QR for `email` and return its SVG."""
	settings = get_settings()

	if not settings.allow_self_service_qr or not settings.qr_login_enabled:
		frappe.throw(generic_generate_failure())

	if not _transport_is_secure(settings):
		frappe.throw(generic_generate_failure())

	if _hit_limit(
		f"qr_selfsvc:ip:{_request_ip()}", GENERATE_IP_LIMIT, GENERATE_IP_WINDOW
	):
		frappe.throw(generic_generate_failure())

	clean = (email or "").strip().lower()
	if _hit_limit(
		f"qr_selfsvc:em:{hashlib.sha256(clean.encode()).hexdigest()[:16]}",
		GENERATE_EMAIL_LIMIT,
		GENERATE_EMAIL_WINDOW,
	):
		frappe.throw(generic_generate_failure())

	user = _resolve_account(clean)
	if not user:
		log_event(
			EVENT_INVALID_CREDENTIAL,
			success=False,
			reason_code=REASON_INVALID_CREDENTIAL,
			details={"channel": "self_service"},
		)
		frappe.throw(generic_generate_failure())

	key = frappe.generate_hash()
	frappe.cache.set_value(_cache_key(key), user, expires_in_sec=EXPIRY_SECONDS)

	from adx_secure_qr_login.security import validation

	log_event(
		EVENT_GENERATED,
		user=user,
		success=True,
		reason_code=REASON_OK,
		details={"channel": "self_service", "expires_in": EXPIRY_SECONDS},
		company=validation.get_user_company(user) or detect_company(),
	)

	return {"svg": qr_image.render_svg(_login_url(key)), "expires_in": EXPIRY_SECONDS}


@frappe.whitelist(allow_guest=True, methods=["GET"])
def consume_login_qr(key: str = None):
	"""Redeem a self-service code: create a normal session, redirect to desk."""
	cache_key = _cache_key(key or "")
	email = frappe.cache.get_value(cache_key)

	if not email:
		frappe.respond_as_web_page(
			frappe._("Not Permitted"),
			frappe._("This QR code is invalid or has expired. Please generate a new one."),
			http_status_code=403,
			indicator_color="red",
		)
		return

	# Single-use: shrink to a grace window so a mobile double-request
	# (prefetch + actual load) still succeeds, then it dies.
	frappe.cache.set_value(cache_key, email, expires_in_sec=CONSUME_GRACE_SECONDS)

	user = _resolve_account(email)
	if not user:
		log_event(
			EVENT_INVALID_CREDENTIAL,
			success=False,
			reason_code=REASON_INVALID_CREDENTIAL,
			details={"channel": "self_service_consume"},
		)
		frappe.respond_as_web_page(
			frappe._("Not Permitted"),
			frappe._("This QR code is invalid or has expired. Please generate a new one."),
			http_status_code=403,
			indicator_color="red",
		)
		return

	settings = get_settings()
	if settings.destroy_prior_session:
		session_guard.destroy_prior_session()

	_sign_in_and_redirect(user)


def _sign_in_and_redirect(user: str) -> None:
	"""Create the normal session and redirect. Split out for testability."""
	from adx_secure_qr_login.security import validation

	frappe.local.login_manager.login_as(user)

	log_event(
		EVENT_LOGIN_SUCCESS,
		user=user,
		success=True,
		reason_code=REASON_OK,
		details={"channel": "self_service"},
		session_reference=session_guard.session_reference(frappe.session.sid),
		company=validation.get_user_company(user) or detect_company(),
	)

	from frappe.apps import get_default_path
	from frappe.utils import get_url

	frappe.local.response["type"] = "redirect"
	frappe.local.response["location"] = get_url(get_default_path() or "/desk")


@frappe.whitelist(allow_guest=True, methods=["GET"])
def self_service_is_available() -> dict:
	"""Whether the login page should offer QR generation."""
	try:
		settings = get_settings()
		available = bool(
			settings.qr_login_enabled and settings.allow_self_service_qr
		)
	except Exception:
		available = False
	return {"available": available}
