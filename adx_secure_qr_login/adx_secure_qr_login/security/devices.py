# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Device identification and tracking for QR logins.

Frappe has no equivalent of Odoo's `res.device` / `res.device.log`, so the
"which device signed in" concern is expressed as a first-class DocType
(`QR Login Device`) owned by this app. Nothing here touches ERPNext core.

Design notes
------------
* The device id is a hash of the client fingerprint, never the fingerprint
  itself, so the User-Agent string is not stored verbatim in a lookup key.
* Tracking is best-effort. A failure to record a device must never turn a
  successful authentication into a 500 -- it is logged and swallowed.
* A revoked device is *not* silently reused: a revoked row keeps its identity so
  an administrator can see the attempt, and `device_verification` decides whether
  that blocks the login.
"""

import hashlib

import frappe

from adx_secure_qr_login.secure_qr_login.constants import (
	EVENT_DEVICE_REGISTERED,
	EVENT_DEVICE_REVOKED,
	EVENT_DEVICE_TRUSTED,
	EVENT_DEVICE_UNTRUSTED,
	EVENT_SESSION_REVOKED,
	REASON_OK,
)

# The Odoo reference reads this from settings; here it is a module default and
# the settings row supplies the real value.
FALLBACK_BROWSER = "Unknown"
FALLBACK_OS = "Unknown"


def fingerprint(user_agent: str, ip_address: str, user: str) -> str:
	"""Stable, non-reversible device id for this client.

	Scoped to the user so two employees behind the same NAT/kiosk do not collapse
	into one device record.
	"""
	raw = f"{user}|{user_agent or ''}|{ip_address or ''}".encode()
	return hashlib.sha256(raw).hexdigest()[:32]


def current_device_id(user: str) -> str:
	"""Device id for the request being served, derived exactly as tracking does."""
	return fingerprint(
		frappe.get_request_header("User-Agent") or "",
		getattr(frappe.local, "request_ip", None),
		user,
	)


def parse_browser(user_agent: str) -> str:
	"""Best-effort browser name from a User-Agent string.

	Ordered most-specific first: Edge and Opera both advertise "Chrome", and
	Chrome advertises "Safari", so a naive substring check would mislabel them.
	"""
	ua = (user_agent or "").lower()
	if "edg/" in ua or "edge/" in ua:
		return "Edge"
	if "opr/" in ua or "opera" in ua:
		return "Opera"
	if "firefox" in ua:
		return "Firefox"
	if "chrome" in ua or "crios" in ua:
		return "Chrome"
	if "safari" in ua:
		return "Safari"
	return FALLBACK_BROWSER


def parse_os(user_agent: str) -> str:
	"""Best-effort operating system from a User-Agent string."""
	ua = (user_agent or "").lower()
	if "android" in ua:
		return "Android"
	if "iphone" in ua or "ipad" in ua or "ios" in ua:
		return "iOS"
	if "mac os" in ua or "macintosh" in ua:
		return "macOS"
	if "windows" in ua:
		return "Windows"
	if "linux" in ua or "x11" in ua:
		return "Linux"
	return FALLBACK_OS


def track_login(user: str) -> str | None:
	"""Record the device behind a successful QR login.

	Returns the device docname, or None when tracking is disabled or failed.
	"""
	if not user:
		return None

	try:
		from adx_secure_qr_login.secure_qr_login.doctype.qr_security_settings.qr_security_settings import (
			get_settings,
		)
		from adx_secure_qr_login.security.validation import get_user_company

		if not get_settings().device_tracking:
			return None

		user_agent = frappe.get_request_header("User-Agent") or ""
		ip_address = getattr(frappe.local, "request_ip", None)
		device_id = current_device_id(user)

		existing = frappe.db.exists(
			"QR Login Device", {"device_id": device_id, "user": user}
		)

		if existing:
			# Re-seen: refresh only the volatile fields. `company` is deliberately
			# left alone -- it mirrors the user's company, and a transient request
			# default must not rewrite the isolation boundary.
			frappe.db.set_value(
				"QR Login Device",
				existing,
				{"last_seen": frappe.utils.now(), "ip_address": ip_address},
				update_modified=False,
			)
			return existing

		doc = frappe.get_doc(
			{
				"doctype": "QR Login Device",
				"device_id": device_id,
				"device_name": f"{parse_browser(user_agent)} on {parse_os(user_agent)}",
				"user": user,
				"company": get_user_company(user),
				"browser": parse_browser(user_agent),
				"operating_system": parse_os(user_agent),
				"ip_address": ip_address,
				"first_seen": frappe.utils.now(),
				"last_seen": frappe.utils.now(),
			}
		)
		doc.flags.ignore_permissions = True
		doc.insert(ignore_permissions=True)

		log_device_event(EVENT_DEVICE_REGISTERED, user=user, device=doc.name)
		return doc.name
	except Exception:
		frappe.log_error(
			title="QR device tracking failed", message=frappe.get_traceback()
		)
		return None


def is_trusted_for(user: str, device_id: str) -> bool:
	"""Whether this device may be used, honouring `device_verification`.

	`log_only`      -- always allowed; the device is recorded for context.
	`require_trusted` -- a device that exists but has been revoked is refused.
	"""
	from adx_secure_qr_login.secure_qr_login.doctype.qr_security_settings.qr_security_settings import (
		get_settings,
	)

	if get_settings().device_verification != "require_trusted":
		return True

	row = frappe.db.get_value(
		"QR Login Device",
		{"device_id": device_id, "user": user},
		["name", "revoked", "trusted"],
		as_dict=True,
	)
	if not row:
		# Never seen before. Requiring trust would make the very first login of
		# every device impossible, so an unknown device is allowed and recorded.
		return True
	return not row.get("revoked")


def revoke_device(device: str, actor: str | None = None) -> int:
	"""Mark a device revoked, end the owner's live sessions, and audit it.

	Assumes authorization already passed. Returns the number of sessions closed.

	Sessions are not bound to a device in Frappe (a session is keyed on sid), so
	"terminate the device's session" can only mean ending the owner's live
	sessions -- the same mechanism credential revocation uses. Skipped when the
	device was already revoked, so a repeat call never logs anyone out.
	"""
	doc = frappe.get_doc("QR Login Device", device)
	if doc.revoked:
		return 0
	doc.revoked = 1
	doc.revoked_on = frappe.utils.now()
	doc.revoked_by = actor or frappe.session.user
	doc.flags.ignore_permissions = True
	doc.save(ignore_permissions=True)
	log_device_event(
		EVENT_DEVICE_REVOKED, user=doc.user, device=device, actor=actor
	)

	from adx_secure_qr_login.security import session_guard

	terminated = session_guard.terminate_user_sessions(
		doc.user, reason=f"QR device {device} revoked"
	)
	if terminated:
		log_device_event(
			EVENT_SESSION_REVOKED,
			user=doc.user,
			device=device,
			actor=actor,
			extra={"sessions_terminated": terminated, "trigger": "device_revoked"},
		)
	return terminated


def set_trusted(device: str, trusted: bool, actor: str | None = None) -> bool:
	"""Mark or unmark a device as trusted and audit the change.

	Assumes authorization already passed. Returns True when the state changed.
	A revoked device cannot be marked trusted.
	"""
	doc = frappe.get_doc("QR Login Device", device)

	if trusted and doc.revoked:
		frappe.throw(
			frappe._("A revoked device cannot be marked as trusted."),
			frappe.ValidationError,
		)

	if bool(doc.trusted) == bool(trusted):
		return False

	doc.trusted = 1 if trusted else 0
	doc.flags.ignore_permissions = True
	doc.save(ignore_permissions=True)
	log_device_event(
		EVENT_DEVICE_TRUSTED if trusted else EVENT_DEVICE_UNTRUSTED,
		user=doc.user,
		device=device,
		actor=actor,
	)
	return True


def log_device_event(
	event: str,
	*,
	user: str,
	device: str,
	actor: str | None = None,
	extra: dict | None = None,
):
	from adx_secure_qr_login.secure_qr_login.doctype.qr_login_audit.qr_login_audit import (
		log_event,
	)

	return log_event(
		event,
		user=user,
		success=True,
		reason_code=REASON_OK,
		actor=actor or frappe.session.user,
		details={"device": device, **(extra or {})},
	)