# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Row-level scoping for QR Login Credential.

Two design traps this module exists to avoid:

1. `if_owner` is the wrong scoping tool here. The owner of a credential is
   whoever *issued* it -- normally a QR Manager -- not the user the credential
   authenticates. `if_owner` would lock John out of his own credential while
   doing nothing to stop a Manager from seeing everyone's. The DocPerm row for
   `Desk User` therefore carries `read` with **no** `if_owner`, and all scoping is
   done here by subject.

2. The role is `Desk User`, not `System User`. Frappe v16 defines
   `SYSTEM_USER_ROLE = "Desk User"` (frappe/permissions.py:35) and never grants a
   role named "System User" to anybody, so a DocPerm row naming it is silently
   inert.

Frappe ANDs the query condition with any `if_owner` restriction rather than
letting the hook override it, so both of the above must be correct in the JSON as
well as in code.
"""

import frappe

from adx_secure_qr_login.security.rbac import can_manage_credentials


def get_permission_query_conditions(user: str | None = None) -> str | None:
	"""Return a SQL fragment, or None when the user may see every row."""
	user = user or frappe.session.user

	if user == "Administrator" or can_manage_credentials(user):
		return None

	# Escaping matters: `user` is a session value, but it is still data and this
	# is still string-built SQL.
	return f"`tabQR Login Credential`.`user` = {frappe.db.escape(user)}"


def has_permission(doc, ptype: str, user: str | None = None) -> bool:
	"""Document-level check, mirroring the query condition above.

	Frappe calls `has_permission` hooks in addition to, not instead of, the query
	condition. Both are needed: the condition narrows lists, this stops a direct
	fetch of a single known docname -- for example through
	`frappe.client.get_value`, which calls `frappe.has_permission()`.

	Every ptype is decided by the same rule. There is deliberately no "always
	allow read" fallback: such a branch would hand every desk user read access to
	every other user's credential, which is exactly what this hook exists to
	prevent.
	"""
	user = user or frappe.session.user

	if user == "Administrator" or can_manage_credentials(user):
		return True

	# Subject or issuer of this specific credential.
	return doc.get("user") == user or doc.get("owner") == user
