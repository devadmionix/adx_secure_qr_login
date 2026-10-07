# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Row-level scoping for QR Login Device.

Device management respects company isolation:
- Administrator / QR Admin: all devices.
- QR Manager: only devices for users inside their company scope.
- Everyone else: only their own devices.
"""

import frappe

from adx_secure_qr_login.security.rbac import (
	can_manage_credentials,
	is_qr_admin,
	visible_users_for_manager,
)


def get_permission_query_conditions(user: str | None = None) -> str | None:
	"""Return a SQL fragment, or None when the user may see every row.

	Company boundary rule:
	- Administrator / QR Admin: all devices.
	- QR Manager: only devices whose subject user sits inside the
	  companies this manager is explicitly permitted to see.
	- Everyone else: only their own devices.
	"""
	user = user or frappe.session.user

	if user == "Administrator" or is_qr_admin(user):
		return None

	if can_manage_credentials(user):
		visible = visible_users_for_manager(user)
		if visible is None:
			return None
		if not visible:
			return "1 = 0"
		names = ", ".join(frappe.db.escape(v) for v in visible)
		return f"`tabQR Login Device`.`user` IN ({names})"

	# Ordinary user: only their own devices.
	return f"`tabQR Login Device`.`user` = {frappe.db.escape(user)}"


def has_permission(doc, ptype: str, user: str | None = None) -> bool:
	"""Document-level check, mirroring the query condition above.

	Frappe calls `has_permission` hooks in addition to, not instead of, the query
	condition. Both are needed: the condition narrows lists, this stops a direct
	fetch of a single known docname.
	"""
	user = user or frappe.session.user

	if user == "Administrator" or is_qr_admin(user):
		return True

	if can_manage_credentials(user):
		visible = visible_users_for_manager(user)
		if visible is None:
			return True
		return doc.get("user") in (visible or [])

	# Ordinary user: only their own devices.
	return doc.get("user") == user
