# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Server-side authorization helpers.

Every function here does its own role evaluation rather than leaning on
`frappe.only_for()` or `frappe.has_permission()`. Both of those short-circuit to
True for the Administrator user, which is correct behaviour for the framework but
makes them useless as the *only* gate in a code path that must also be provably
correct for ordinary users. The Phase 5 permission tests assert that a plain
`Sales User` is rejected; that assertion is meaningless if the helper would have
let them through anyway under an Administrator-only test.
"""

import frappe

from adx_secure_qr_login.secure_qr_login.constants import (
	EVENT_UNAUTHORIZED_MANAGEMENT,
	REASON_UNAUTHORIZED,
	ROLE_ADMIN,
	ROLE_MANAGER,
	LEGACY_ROLE_ADMIN,
)

# Roles that must never be reachable through a QR Manager action. Granting or
# re-minting credentials for a peer administrator is a privilege-escalation path,
# so a Manager must escalate to an Admin to touch one of these accounts.
PRIVILEGED_ROLES = frozenset({"Administrator", "System Manager", ROLE_ADMIN, LEGACY_ROLE_ADMIN})


def _roles_of(user: str) -> set[str]:
	if not user:
		return set()
	try:
		return set(frappe.get_roles(user))
	except Exception:
		return set()


def is_qr_admin(user: str | None = None) -> bool:
	user = user or frappe.session.user
	if user == "Administrator":
		return True
	return ROLE_ADMIN in _roles_of(user)


def is_qr_manager(user: str | None = None) -> bool:
	user = user or frappe.session.user
	if user == "Administrator":
		return True
	return ROLE_MANAGER in _roles_of(user)


def is_qr_admin_strict(user: str | None = None) -> bool:
	"""Admin check that does *not* honour the Administrator superuser bypass.

	Used where the decision must be attributable to a real role assignment, e.g.
	the weekly report recipient set.
	"""
	user = user or frappe.session.user
	return ROLE_ADMIN in _roles_of(user)


def can_manage_credentials(user: str | None = None) -> bool:
	return is_qr_admin(user) or is_qr_manager(user)


def can_view_credential(credential_name: str, user: str | None = None) -> bool:
	"""Whether `user` may see this credential.

	Owner-scoped for ordinary System Users: a user may always see their own
	credential, plus any they issued themselves.

	QR Admin sees everything. A QR **Manager** does *not*: they are scoped to the
	companies they are permitted to see. Returning True for every manager here
	would let a Company A manager read, download, revoke or regenerate a Company B
	credential purely because they hold the QR Manager role.
	"""
	user = user or frappe.session.user

	if user == "Administrator" or is_qr_admin(user):
		return True

	if not frappe.db.exists("QR Login Credential", credential_name):
		return False

	subject, owner = frappe.db.get_value(
		"QR Login Credential", credential_name, ["user", "owner"], as_dict=False
	) or (None, None)

	if user in (subject, owner):
		return True

	if can_manage_credentials(user):
		# Role is not enough; the subject's company must be inside the manager's
		# permitted scope. `assert_in_manager_scope` raises (and audits) on
		# refusal, so a boolean wrapper is needed here.
		return _subject_in_manager_scope(subject, user)

	return False


def _subject_in_manager_scope(subject: str | None, actor: str) -> bool:
	"""Boolean form of `assert_in_manager_scope` (no raise, no audit).

	Kept next to the raising version deliberately so the two cannot drift: the
	document-level `has_permission` hook needs a bool, the API endpoints need the
	throw-and-audit behaviour.
	"""
	if not subject:
		return False

	allowed = manager_companies(actor)
	if allowed is None:
		# Company scoping is switched off, or the manager holds no Company User
		# Permission (which ERPNext itself treats as unrestricted).
		return True

	subject_companies = _company_permissions(subject)
	if not subject_companies:
		return True

	return bool(subject_companies & allowed)


def _company_permissions(user: str) -> set[str]:
	perms = frappe.get_all(
		"User Permission",
		filters={"user": user, "allow": "Company"},
		fields=["for_value"],
		limit_page_length=0,
		ignore_permissions=True,
	)
	return {p["for_value"] for p in perms}


def assert_can_manage_credential(
	credential_name: str, action: str, user: str | None = None
) -> None:
	"""Raise unless the caller may read *and* administer this credential.

	The single gate for every credential endpoint. It deliberately composes the
	existing checks rather than adding a fourth rule:

	1. `assert_can_view_credential` -- row-level visibility (subject/issuer/company)
	2. `assert_can_manage_credentials` -- the caller holds a QR role at all
	3. `assert_in_manager_scope`  -- the subject's company is inside a manager's
	   permitted scope, audited on refusal

	Steps 1 and 2 alone are not sufficient: a QR Manager passes both for any
	credential in the database, which is what let a Company A manager revoke a
	Company B credential.
	"""
	actor = user or frappe.session.user

	assert_can_view_credential(credential_name, actor)
	assert_can_manage_credentials(action, actor)

	if not can_manage_credentials(actor) or is_qr_admin(actor):
		return

	subject = frappe.db.get_value("QR Login Credential", credential_name, "user")
	assert_in_manager_scope(subject, actor)


def assert_can_manage_credentials(action: str, user: str | None = None) -> None:
	"""Raise unless the caller may manage credentials, recording the attempt."""
	user = user or frappe.session.user
	if can_manage_credentials(user):
		return
	_deny(action, user)


def assert_is_qr_admin(action: str, user: str | None = None) -> None:
	user = user or frappe.session.user
	if is_qr_admin(user):
		return
	_deny(action, user)


def assert_can_manage_target(action: str, target_user: str, user: str | None = None) -> None:
	"""Guard the escalation path: a Manager may not act on a privileged account.

	An Admin is also blocked from minting a credential for `Administrator`
	itself, so there is no way to produce a bearer token for the superuser.
	"""
	assert_can_manage_credentials(action, user)

	actor = user or frappe.session.user
	if target_user == "Administrator":
		_deny(action, actor, detail="target=Administrator")

	if is_qr_admin_strict(actor):
		# Admins may manage any non-superuser account.
		return

	# Defensive: refuse a target that is not a real User document.
	#
	# Without this, a mistyped argument (or a caller passing a role name instead
	# of an email) reaches `_roles_of()`, and `frappe.get_roles()` on a
	# nonexistent user returns only the automatic roles -- so the privileged-role
	# intersection below would pass vacuously and the escalation guard would be
	# skipped. Failing closed costs nothing: callers already validate the user.
	if not frappe.db.exists("User", target_user):
		_deny(action, actor, detail="target_not_a_user")

	if PRIVILEGED_ROLES.intersection(_roles_of(target_user)):
		_deny(action, actor, detail="target_is_privileged")

	# Spec 11: a Manager's reach stops at the companies they can see.
	assert_in_manager_scope(target_user, actor)


def _deny(action: str, user: str, detail: str | None = None) -> None:
	"""Record the denial, then raise.

	The audit write happens before the throw so that a refused attempt is
	evidence even though the request is rejected.
	"""
	from adx_secure_qr_login.secure_qr_login.doctype.qr_login_audit.qr_login_audit import log_event

	log_event(
		EVENT_UNAUTHORIZED_MANAGEMENT,
		success=False,
		reason_code=REASON_UNAUTHORIZED,
		actor=user,
		details={"action": action, **({"scope": detail} if detail else {})},
		commit=True,
	)

	frappe.throw(
		frappe._("You are not permitted to perform this action."),
		frappe.PermissionError,
	)


def assert_can_view_credential(credential_name: str, user: str | None = None) -> None:
	if can_view_credential(credential_name, user):
		return
	# Not audited as "unauthorized management": a read attempt on a credential
	# the caller cannot see is a different, lower-severity event.
	frappe.throw(frappe._("Not permitted"), frappe.PermissionError)


def can_view_user(user: str, actor: str | None = None) -> bool:
	"""Whether `actor` may enumerate a single user's credentials or devices.

	An ordinary System User may only ever enumerate themselves. QR Admin may
	enumerate anyone. A QR Manager is company-scoped: without this check a
	Company A manager could pass any Company B user id to `list_user_credentials`
	and read their whole credential history.
	"""
	actor = actor or frappe.session.user
	if actor == user:
		return True
	if actor == "Administrator" or is_qr_admin(actor):
		return True
	if can_manage_credentials(actor):
		return _subject_in_manager_scope(user, actor)
	return False


def manager_companies(user: str | None = None) -> set[str] | None:
	"""Companies a QR Manager may act within, or None when unrestricted.

	Spec 11: "QR Manager can manage only users/credentials within permitted scope."

	Derived from the manager's own User Permissions on Company -- the same engine
	that already governs what they can see in ERPNext. Returns None (no company
	restriction) when the scope control is disabled, or when the manager has no
	Company User Permission at all, since that mirrors ERPNext's own behaviour for
	an unrestricted user.
	"""
	user = user or frappe.session.user

	try:
		from adx_secure_qr_login.secure_qr_login.doctype.qr_security_settings.qr_security_settings import (
			get_settings,
		)

		if not get_settings().manager_company_scope_enabled:
			return None
	except Exception:
		return None

	perms = _company_permissions(user)
	if not perms:
		return None

	return perms


def assert_in_manager_scope(target_user: str, actor: str | None = None) -> None:
	"""A QR Manager may only act on users inside their permitted companies."""
	actor = actor or frappe.session.user

	if actor == "Administrator" or is_qr_admin_strict(actor):
		return

	if not can_manage_credentials(actor):
		return

	if not _subject_in_manager_scope(target_user, actor):
		_deny("manager_scope", actor, detail="target_outside_company_scope")


def assert_can_view_user(user: str, actor: str | None = None) -> None:
	if can_view_user(user, actor):
		return
	_deny("list_user_credentials", actor or frappe.session.user, detail=f"target_user={user}")


def can_view_device(device_name: str, user: str | None = None) -> bool:
	"""Whether `user` may see this device.

	Owner-scoped for ordinary System Users. QR Admin sees everything; a QR
	Manager is limited to devices belonging to users in their permitted
	companies, so a Company A administrator cannot manage Company B devices.
	"""
	user = user or frappe.session.user

	if user == "Administrator" or is_qr_admin(user):
		return True

	if not frappe.db.exists("QR Login Device", device_name):
		return False

	subject = frappe.db.get_value("QR Login Device", device_name, "user")
	if user == subject:
		return True

	if can_manage_credentials(user):
		return _subject_in_manager_scope(subject, user)

	return False


def assert_can_view_device(device_name: str, user: str | None = None) -> None:
	if can_view_device(device_name, user):
		return
	frappe.throw(frappe._("Not permitted"), frappe.PermissionError)


def assert_can_manage_device(device_name: str, action: str, user: str | None = None) -> None:
	"""Raise unless the caller may administer this specific device.

	Mirrors `assert_can_manage_credential`: the QR role is necessary but not
	sufficient, so the device's owner's company must also be in scope.
	"""
	actor = user or frappe.session.user

	assert_can_view_device(device_name, actor)
	if not can_manage_credentials(actor):
		_deny(action, actor)

	if not is_qr_admin(actor) and actor != "Administrator":
		subject = frappe.db.get_value("QR Login Device", device_name, "user")
		if not _subject_in_manager_scope(subject, actor):
			_deny(action, actor, detail="device_outside_company_scope")


def assert_can_manage_devices(user: str | None = None) -> None:
	"""Raise unless the caller holds a device-management role at all.

	Role-level gate only; per-record company scoping is
	`assert_can_manage_device`.
	"""
	user = user or frappe.session.user
	if can_manage_credentials(user):
		return
	_deny("manage_devices", user)


def visible_users_for_manager(actor: str | None = None) -> list[str] | None:
	"""Users a QR Manager may see in the audit trail, honouring company scope.

	Returns None when the caller is unrestricted (Administrator, QR Admin, or a
	Manager whose company scope is switched off), which callers read as "no
	restriction" rather than as an empty set.
	"""
	actor = actor or frappe.session.user

	if is_qr_admin(actor) or actor == "Administrator":
		return None

	allowed = manager_companies(actor)
	if allowed is None:
		return None

	return sorted(
		u
		for u in (
			frappe.get_all(
				"User Permission",
				filters={"allow": "Company", "for_value": ("in", list(allowed))},
				pluck="user",
				limit_page_length=0,
				ignore_permissions=True,
			)
			if allowed
			else []
		)
		if not PRIVILEGED_ROLES.intersection(_roles_of(u))
	)
