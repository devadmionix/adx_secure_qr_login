# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Correct the self-service permission row and drop the stray Role it created.

Phase 2 granted `System User` owner-scoped read on QR Login Credential. No such
role is ever assigned in Frappe v16 -- `frappe/permissions.py:35` defines
`SYSTEM_USER_ROLE = "Desk User"`, and `get_roles()` appends that instead. The
DocPerm row was therefore inert: every desk user got "Insufficient Permission"
and nobody could see their own credential.

Frappe's permission sync helpfully auto-created a Role record for the unknown
"System User" (frappe/core/doctype/doctype/doctype.py:1989-1997), which is why
the mistake was invisible rather than an error. Nothing in Frappe or ERPNext
references a role by that name, so it is removed here.
"""

import frappe

STRAY_ROLE = "System User"
CORRECT_ROLE = "Desk User"


def execute():
	# The Desk User role is created by Frappe itself; guard anyway.
	if not frappe.db.exists("Role", CORRECT_ROLE):
		role = frappe.get_doc({"doctype": "Role", "role_name": CORRECT_ROLE, "desk_access": 1})
		role.flags.ignore_mandatory = role.flags.ignore_permissions = True
		role.insert()

	# Only remove the stray role if it is genuinely unused.
	if frappe.db.exists("Role", STRAY_ROLE) and not frappe.db.exists(
		"Has Role", {"role": STRAY_ROLE, "parenttype": "User"}
	):
		try:
			frappe.delete_doc("Role", STRAY_ROLE, force=True, ignore_permissions=True)
		except Exception:
			frappe.log_error(title="Stray 'System User' role cleanup failed",
							 message=frappe.get_traceback())

	frappe.clear_cache()
	frappe.db.commit()
