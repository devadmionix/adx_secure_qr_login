# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Row-level scoping for QR Login Audit.

The audit trail is security evidence, so the default is restrictive: QR Admin sees
everything, a QR Manager sees only rows concerning users they are permitted to
manage. There is no blanket "any desk user may read the audit log" -- that is
explicitly called out as forbidden in the specification.

`permission_query_conditions` narrows list and report queries;
`has_permission` stops a direct fetch of a single known docname.
"""

import frappe

from adx_secure_qr_login.security.rbac import (
	can_manage_credentials,
	is_qr_admin,
	visible_users_for_manager,
)


def _visible_users(user: str) -> list[str] | None:
	"""Users whose audit rows `user` may see, or None for unrestricted.

	For a Manager this is every System User who does not hold a privileged role
	*and* sits inside the companies that Manager can access (spec 11). A Manager
	has no business reading the security history of a System Manager or a peer QR
	Admin, and cannot act on those accounts either -- see
	`security.rbac.assert_can_manage_target`.
	"""
	if is_qr_admin(user):
		return None

	# Company scope first: it is the cheaper and more restrictive filter.
	scoped = visible_users_for_manager(user)
	if scoped is not None:
		return scoped

	candidates = frappe.get_all(
		"User",
		filters={"user_type": "System User"},
		pluck="name",
		limit_page_length=0,
	)
	privileged = {"Administrator", "System Manager", "QR Admin"}

	visible = []
	for name in candidates:
		roles = set(frappe.get_roles(name))
		if roles & privileged:
			continue
		visible.append(name)

	# A row with no resolved user (an unknown token, a rate-limited probe) is
	# visible to Managers: those events contain no user identity at all.
	return visible


def get_permission_query_conditions(user: str | None = None) -> str | None:
	user = user or frappe.session.user

	if user == "Administrator" or can_manage_credentials(user):
		if is_qr_admin(user) or user == "Administrator":
			return None
		visible = _visible_users(user)
		if visible is None:
			return None
		if not visible:
			# No visible users at all: return an impossible predicate rather than
			# an empty IN () which would be a syntax error.
			return "1 = 0"
		names = ", ".join(frappe.db.escape(v) for v in visible)
		return (
			f"(`tabQR Login Audit`.`user` IN ({names})"
			f" OR `tabQR Login Audit`.`user` IS NULL"
			f" OR `tabQR Login Audit`.`actor` = {frappe.db.escape(user)})"
		)

	# Ordinary desk user: no audit access whatsoever.
	return "1 = 0"


def has_permission(doc, ptype: str, user: str | None = None) -> bool:
	user = user or frappe.session.user

	if user == "Administrator" or is_qr_admin(user):
		return True

	if not can_manage_credentials(user):
		return False

	subject = doc.get("user")
	if not subject:
		# Unattributed events (unknown token, rate limit) carry no user identity.
		return True

	return subject in set(_visible_users(user) or []) or doc.get("actor") == user
