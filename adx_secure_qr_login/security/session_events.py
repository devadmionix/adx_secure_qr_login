"""Account and session lifecycle events: USER_DISABLED, SESSION_REVOKED (spec 14)."""

import frappe

from frappe.sessions import clear_sessions

from adx_secure_qr_login.secure_qr_login.constants import (
	EVENT_SESSION_REVOKED,
	EVENT_USER_DISABLED,
	REASON_OK,
)

# Key under `doc.flags` holding the account's enabled state as it was in the
# database before this save. `User` is saved by many routes -- impersonation,
# profile edits, profile picture updates -- so the transition has to be detected
# against the stored value, not against "a save happened".
PREV_ENABLED_FLAG = "_qr_previous_enabled"


def capture_previous_state(doc, method=None) -> None:
	"""`User.on_update` fires after the row is written, so read the old value here."""
	if not doc.flags.get("_qr_state_captured"):
		doc.flags[PREV_ENABLED_FLAG] = frappe.db.get_value(
			"User", doc.name, "enabled", cache=False
		)
		doc.flags["_qr_state_captured"] = True


def record_user_disabled(doc, method=None) -> None:
	"""Audit an account being disabled and close the QR sessions it still holds.

	Spec 14 USER_DISABLED and spec 8: disabling an account must not leave live
	sessions authenticated as a user who should no longer have access.
	"""
	was_enabled = doc.flags.get(PREV_ENABLED_FLAG)

	# Only a true Active -> Disabled transition is interesting. Re-enabling, and
	# every ordinary profile save, are skipped.
	if was_enabled != 1 or doc.get("enabled"):
		return

	from adx_secure_qr_login.security import session_guard
	from adx_secure_qr_login.secure_qr_login.doctype.qr_login_audit.qr_login_audit import log_event

	terminated = session_guard.terminate_user_sessions(
		doc.name, reason="User account disabled"
	)
	# No explicit commit here. This hook runs inside the caller's `User` save,
	# so committing would also commit a document that is still mid-save: a
	# failure in a later validator would leave the user half-written. The
	# disable, the session deletions and the audit rows belong to the caller's
	# one transaction, which frappe commits at the end of the request.
	log_event(
		EVENT_USER_DISABLED,
		user=doc.name,
		success=True,
		reason_code=REASON_OK,
		actor=frappe.session.user,
		details={"sessions_terminated": terminated},
		commit=False,
	)

	if terminated:
		log_event(
			EVENT_SESSION_REVOKED,
			user=doc.name,
			success=True,
			reason_code=REASON_OK,
			actor=frappe.session.user,
			details={"sessions_terminated": terminated, "trigger": "user_disabled"},
			commit=False,
		)


def terminate_sessions(user: str, reason: str | None = None) -> int:
	"""Close every live Frappe session for `user` (spec 8).

	Wraps frappe's own `clear_sessions` so the redis keys are dropped too, and
	records the action so a forced logout is never invisible in the audit trail.

	Returns the number of sessions closed.
	"""
	from adx_secure_qr_login.security import rbac
	from adx_secure_qr_login.secure_qr_login.doctype.qr_login_audit.qr_login_audit import log_event

	rbac.assert_is_qr_admin("terminate_sessions")

	if not user or user in ("", "Guest"):
		frappe.throw(frappe._("A user is required."), frappe.ValidationError)

	if not frappe.db.exists("User", user):
		# Same message shape as a valid-but-invisible user, so the endpoint cannot
		# be used to enumerate accounts.
		frappe.throw(
			frappe._("User {0} does not exist or is outside your scope.").format(user),
			frappe.DoesNotExistError,
		)

	before = frappe.db.sql("SELECT COUNT(*) FROM tabSessions WHERE `user` = %s", (user,))[0][0]

	clear_sessions(user, force=True)
	# No explicit commit: the only caller is the POST endpoint
	# `api.qr_manage.terminate_user_sessions`, and frappe commits a mutating
	# request once the response is produced (frappe/app.py:466). The deletes are
	# visible to the `after` count below either way -- same transaction,
	# same connection.

	after = frappe.db.sql("SELECT COUNT(*) FROM tabSessions WHERE `user` = %s", (user,))[0][0]
	terminated = max(before - after, 0)

	log_event(
		EVENT_SESSION_REVOKED,
		user=user,
		success=True,
		reason_code=REASON_OK,
		actor=frappe.session.user,
		details={"sessions_terminated": terminated, "trigger": "admin_action"},
		commit=True,
	)

	return terminated