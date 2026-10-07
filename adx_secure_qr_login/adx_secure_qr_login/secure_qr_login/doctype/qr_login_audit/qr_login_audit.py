# Copyright (c) 2026, ADmionix Solutions
# License: MIT

import frappe
from frappe.model.document import Document

from adx_secure_qr_login.secure_qr_login.constants import (
	REASON_OK,
	TOKEN_HASH_FIELD,
	TOKEN_PREFIX_LENGTH,
)

# Field names that must never reach the database. The audit writer scrubs these
# out of any detail payload it is handed, so a caller cannot accidentally persist
# credential material by passing it through as free text.
_FORBIDDEN_DETAIL_KEYS = frozenset(
	{TOKEN_HASH_FIELD, "token", "qr_token", "secret", "password", "raw_token"}
)


class QRLoginAudit(Document):
	"""Append-only security event log.

	Deliberately has no create/write/delete DocType permission for any role: rows
	are only ever written by `log_event` below, which ignores permissions. A
	privileged user who needs to remove data must go through a patch, which leaves
	an explicit trail.
	"""

	# doctype: qr.login.audit

	def before_insert(self):
		if not self.occurred_on:
			self.occurred_on = frappe.utils.now()

	def validate(self):
		if self.is_new():
			return
		# Once written, an audit row is immutable. UPDATE is the only mutation
		# path that would otherwise let history be quietly rewritten.
		frappe.throw(
			frappe._("Audit records cannot be modified after creation."),
			frappe.PermissionError,
		)

	def on_trash(self):
		# Administrators (QR Admin / System Manager) may delete through the
		# normal UI; everyone else is blocked. This keeps the audit trail
		# from being shortened by mistake, while still letting the owner
		# erase it temporarily as they've asked.
		from adx_secure_qr_login.security.rbac import is_qr_admin

		if frappe.session and (
			frappe.session.user == "Administrator" or is_qr_admin(frappe.session.user)
		):
			return
		frappe.throw(
			frappe._("Audit records cannot be deleted."),
			frappe.PermissionError,
		)


def scrub_details(details: dict | None) -> str:
	"""Flatten a detail mapping into a short, non-sensitive string."""
	if not details:
		return ""

	safe = {}
	for key, value in details.items():
		if str(key).lower() in _FORBIDDEN_DETAIL_KEYS:
			continue
		if value is None or isinstance(value, (int, float, bool)):
			safe[key] = value
		else:
			safe[key] = str(value)[:200]

	return ", ".join(f"{k}={v}" for k, v in sorted(safe.items()))[:500]


def request_context() -> dict:
	"""Non-sensitive facts about the current request."""
	ctx = {"ip_address": getattr(frappe.local, "request_ip", None)}

	if frappe.request:
		user_agent = frappe.get_request_header("User-Agent")
		if user_agent:
			# Truncated: audit rows must not become a storage sink for long
			# attacker-controlled strings.
			ctx["user_agent"] = user_agent[:255]

	return ctx


def detect_company(user: str | None = None) -> str | None:
	"""Best-effort company context for an audit row.

	Never authoritative: it is whatever the acting user's own default company
	happens to be, recorded for context only. Authorization never reads it.

	Deliberately *not* `frappe.defaults.get_user_default`, which merges in the
	site-wide `__default` row (and would stamp every audit row with the site's
	company even when the user never chose one). This reads only the rows
	belonging to `user`, so an absent default yields no company rather than a
	misleading one.
	"""
	user = user or frappe.session.user

	if not user or user == "Guest":
		return None

	try:
		return frappe.defaults.get_defaults_for(user).get("Company") or None
	except Exception:
		return None


def log_event(
	event: str,
	*,
	user: str | None = None,
	credential: str | None = None,
	success: bool = False,
	reason_code: str | None = None,
	details: dict | None = None,
	terminal_label: str | None = None,
	actor: str | None = None,
	session_reference: str | None = None,
	company: str | None = None,
	commit: bool = True,
) -> str:
	"""Write one audit row.

	Never raises: a failure to record an event must not turn into a login outage,
	and must never leak the reason a credential was rejected back to the caller.

	`session_reference` must be the *hashed* short form from
	`session_guard.session_reference()`. The raw sid is a bearer credential and is
	never stored.
	"""
	if not _audit_enabled():
		return ""

	try:
		row = {
			"doctype": "QR Login Audit",
			"event": event,
			"success": 1 if success else 0,
			"reason_code": reason_code or REASON_OK,
			"occurred_on": frappe.utils.now(),
			"actor": actor if actor is not None else (frappe.session.user or None),
			"details": scrub_details(details),
			"terminal_label": terminal_label,
			"session_reference": session_reference,
			**request_context(),
		}
		if user:
			row["user"] = user
		if credential:
			row["credential"] = credential
		if company:
			row["company"] = company

		doc = frappe.get_doc(row)
		doc.flags.ignore_permissions = True
		doc.flags.ignore_permissions_on_insert = True
		doc.insert(ignore_permissions=True)
		if commit:
			frappe.db.commit()
		return doc.name
	except Exception:
		# Deliberately swallow. The caller's job is to reject or accept the
		# credential; audit bookkeeping is secondary and must not change that
		# outcome or surface internal detail.
		frappe.log_error(
			title="QR Login Audit write failed",
			message=frappe.get_traceback(),
		)
		return ""


def _audit_enabled() -> bool:
	"""Honour the `audit_logging_enabled` setting, defaulting to on.

	Defaults to True when the settings row is unreadable: audit logging failing
	open would silently lose security history, which is the worse failure.
	"""
	try:
		from adx_secure_qr_login.secure_qr_login.doctype.qr_security_settings.qr_security_settings import (
			get_settings,
		)

		return bool(get_settings().audit_logging_enabled)
	except Exception:
		return True
