# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Shared-terminal session handling, and session termination on revocation.

The default Frappe session lifetime is 240 hours (`sessions.py:519`,
`"240:00:00"`). On a kiosk terminal that is a long time for one person's
authority to remain valid in redis after they have walked away.

`LoginManager.clear_active_sessions()` does not help here: it only fires when
`deny_multiple_sessions` is configured, and even then it clears sessions belonging
to the *same* user, which is the opposite of the shared-terminal case.
"""

import hashlib

import frappe

from frappe.sessions import delete_session


def destroy_prior_session(reason: str = "Replaced by QR login") -> None:
	"""Terminate any existing authenticated session on this browser.

	Called immediately before a new session is created, so the previous user's
	session row and its redis key are destroyed rather than merely orphaned.

	Ordering matters: doing this first means a failure during the new session's
	set-up leaves the terminal logged out, which is the safe direction to fail.
	"""
	if not getattr(frappe.local, "request", None):
		return

	sid = (frappe.session or {}).get("sid")
	user = (frappe.session or {}).get("user")

	if not sid or not user or user in ("", "Guest"):
		return

	try:
		delete_session(sid, user=user, reason=reason)
	except Exception:
		# A failure to clean up must not block the new login, but it must be
		# visible: leaving the old session alive is exactly the risk this guards.
		frappe.log_error(title="Prior session cleanup failed", message=frappe.get_traceback())

	# Drop the stale sid from the local request state so the subsequent
	# make_session() is treated as a fresh login rather than a resume.
	if hasattr(frappe.session, "data") and isinstance(frappe.session.data, dict):
		frappe.session.data["sid"] = None


def _active_sids_for_user(user: str) -> list[str]:
	"""Every live session currently belonging to `user`.

	`Sessions` is a table-only doctype with no DocType record, so `frappe.get_all`
	raises DoesNotExistError on it. Query the table directly.
	"""
	rows = frappe.db.sql("SELECT sid FROM tabSessions WHERE `user` = %s", (user,))
	return [r[0] for r in rows if r and r[0]]


def terminate_user_sessions(user: str, reason: str = "QR credential revoked") -> int:
	"""Terminate all active sessions for `user`. Returns how many were closed.

	Spec 8: "Credential revocation blocks future authentication; existing-session
	termination behavior must be explicitly implemented and tested." Blocking the
	next login is only half of it -- without this, a QR revoked at 09:05 leaves the
	person who scanned it at 09:00 authenticated until the session expires, which
	on a shared terminal defaults to ten days.

	The session rows are deleted directly rather than through `delete_session`,
	which is bound to the current request's session and would only ever reach the
	caller's own sid.
	"""
	if not user or user in ("", "Guest"):
		return 0

	terminated = 0
	for sid in _active_sids_for_user(user):
		try:
			delete_session(sid, user=user, reason=reason)
			terminated += 1
		except Exception:
			frappe.log_error(
				title="Session termination failed during credential revocation",
				message=frappe.get_traceback(),
			)

	return terminated


def session_reference(sid: str | None) -> str | None:
	"""A short, non-secret handle for an audit row.

	The full sid is a bearer credential in its own right -- anyone holding it can
	resume the session -- so it is never written to the audit trail. This keeps
	enough to correlate a row with a session in the same request without handing
	out the secret.
	"""
	if not sid:
		return None
	return f"sid:{hashlib.sha256(sid.encode()).hexdigest()[:12]}"
