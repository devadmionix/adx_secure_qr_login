# Copyright (c) 2026, ADmionix Solutions
# License: MIT

import frappe


def before_uninstall():
	"""Remove the QR roles from users before the app is torn down.

	Roles are left in the database on purpose: dropping a Role that Has Role rows
	still reference leaves orphaned assignments. `frappe.delete_doc("Role", ...)`
	is deliberately not called.
	"""
	for role in ("QR Login Manager", "QR Login Admin", "QR Manager", "QR Admin"):
		if not frappe.db.exists("Role", role):
			continue
		users = frappe.get_all(
			"Has Role",
			filters={"role": role, "parenttype": "User"},
			pluck="parent",
		)
		for user in users:
			if not frappe.db.exists("User", user):
				continue
			doc = frappe.get_doc("User", user)
			doc.remove_roles(role)

	# No explicit commit: `frappe.installer.uninstall_app` commits the uninstall
	# transaction once every hook has run, so a failure part way through still
	# rolls the role removals back with everything else.
