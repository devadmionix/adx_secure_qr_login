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
import time

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

	# The sessions are gone, so they must stop occupying concurrent-session slots.
	release_qr_session(user)

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


def check_concurrent_sessions(user: str) -> bool:
	"""Whether `user` may open another QR session.

	Counts only sessions established *through QR login*, which is what the limit
	is about. Counting every Frappe session would count password logins too and
	lock a user out of their own desk session because somebody else used a
	password elsewhere.

	The registry is a Redis hash of sid -> epoch, one key per user. Redis was
	chosen over `tabSessions` because that is a framework-internal table whose
	columns differ between Frappe versions, and because the entry expires on its
	own when the process dies.
	"""
	from adx_secure_qr_login.secure_qr_login.doctype.qr_security_settings.qr_security_settings import (
		get_settings,
	)

	max_sessions = get_settings().max_concurrent_sessions or 0
	if max_sessions <= 0:
		# 0 means unlimited -- the default, so shared terminals are unaffected.
		return True

	return len(_live_qr_sessions(user)) < max_sessions


# Key holding the live QR sessions of one user: a Redis hash of sid -> epoch.
QR_SESSIONS_KEY = "qr_sessions:{0}"

# A QR session older than this is treated as gone even if its key survives.
# Frappe's default session lifetime is 240h; anything older is not a session
# anyone can still resume.
QR_SESSION_TTL = 240 * 60 * 60


def _live_qr_sessions(user: str) -> dict:
	"""Live QR sessions for `user`, pruned of entries past the session lifetime.

	Pruning here rather than relying purely on the Redis TTL means a stale sid can
	never consume a slot forever if the TTL was extended somewhere.
	"""
	key = QR_SESSIONS_KEY.format(user)
	try:
		sessions = frappe.cache.hgetall(key) or {}
	except Exception:
		# Never let the bookkeeping break an authentication decision.
		return {}

	cutoff = time.time() - QR_SESSION_TTL
	live = {sid: ts for sid, ts in sessions.items() if _as_float(ts) >= cutoff}

	if len(live) != len(sessions):
		try:
			frappe.cache.delete_value(key)
			for sid, ts in live.items():
				frappe.cache.hset(key, sid, ts)
			if live:
				frappe.cache.expire(key, QR_SESSION_TTL)
		except Exception:
			pass

	return live


def _as_float(value) -> float:
	try:
		return float(value)
	except (TypeError, ValueError):
		return 0.0


def register_qr_session(user: str, sid: str | None = None) -> None:
	"""Record a QR-established session so the concurrent cap can count it."""
	if not user or not sid:
		return
	try:
		key = QR_SESSIONS_KEY.format(user)
		frappe.cache.hset(key, sid, time.time())
		frappe.cache.expire(key, QR_SESSION_TTL)
	except Exception:
		frappe.log_error(
			title="QR session registry update failed",
			message=frappe.get_traceback(),
		)


def release_qr_session(user: str, sid: str | None = None) -> None:
	"""Drop a QR session from the registry (logout, revocation, disable)."""
	if not user:
		return
	try:
		key = QR_SESSIONS_KEY.format(user)
		if sid:
			frappe.cache.hdel(key, sid)
		else:
			# No specific sid (e.g. the user was disabled): clear everything.
			frappe.cache.delete_value(key)
	except Exception:
		pass
