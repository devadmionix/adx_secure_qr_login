# Copyright (c) 2026, ADmionix Solutions
# License: MIT

import frappe

from adx_secure_qr_login.secure_qr_login.constants import (
	ROLE_ADMIN,
	ROLE_MANAGER,
	QR_ROLES,
	LEGACY_ROLE_ADMIN,
	LEGACY_ROLE_MANAGER,
)

# Roles are created here rather than shipped as fixtures, following the pattern
# ERPNext uses in erpnext/setup/install.py: idempotent, explicit, and rerunnable.
ROLES = (ROLE_MANAGER, ROLE_ADMIN)


def before_install():
	"""No pre-install work is required.

	Roles are created in `after_install` alongside the settings single so a
	failure part-way through leaves no half-created role set.
	"""


def after_install():
	create_roles()
	seed_settings()
	add_roles_to_administrator()
	ensure_desk_navigation()
	frappe.db.commit()


def after_migrate():
	"""Re-assert desk navigation and rename legacy roles after every migrate.

	`bench migrate` regenerates `Workspace Sidebar` from the module, which drops
	anything a one-shot patch added. Without this the QR Security Dashboard
	shortcut silently disappears from the sidebar on an upgraded site, leaving it
	reachable only by URL. The helper is idempotent, so calling it on every
	migrate is safe.

	Also renames legacy role names ("QR Admin" -> "QR Login Admin",
	"QR Manager" -> "QR Login Manager") so sites installed before the rename
	are brought in line without manual intervention.

	Finally clears the app's own module from any user's blocked-modules list: a
	Module Profile applied before this app was installed can leave
	"Secure QR Login" blocked, and Frappe then hides the workspace from the desk
	sidebar entirely (see `desktop.get_workspaces`). The app is meant to be
	reachable by ordinary desk users, so the stale block is removed.
	"""
	rename_legacy_roles()
	unblock_qr_module()
	ensure_desk_navigation()


APP_MODULE = "Secure QR Login"


def unblock_qr_module():
	"""Remove the app's module from every user's blocked-modules list.

	Idempotent and quiet. A module listed in `User.block_modules` is filtered out
	of `desktop.get_workspaces()`, so the workspace disappears from the sidebar
	even though the user holds `Desk User`. That list is normally populated from a
	Module Profile; one created before this app existed will not contain it, but
	an older sync can still have left the module blocked.
	"""
	try:
		frappe.db.delete(
			"Block Module",
			{"parenttype": "User", "parentfield": "block_modules", "module": APP_MODULE},
		)
		frappe.clear_cache()
	except Exception:
		frappe.log_error(
			title="QR module unblock failed", message=frappe.get_traceback()
		)


def rename_legacy_roles():
	"""Rename legacy role records to the current canonical names.

	Idempotent: skips roles that have already been renamed or do not exist.
	Also updates the Administrator user's role assignments.
	"""
	renames = [
		(LEGACY_ROLE_ADMIN, ROLE_ADMIN),
		(LEGACY_ROLE_MANAGER, ROLE_MANAGER),
	]

	for old_name, new_name in renames:
		if not frappe.db.exists("Role", old_name):
			continue
		if frappe.db.exists("Role", new_name):
			# New role already exists; the old one may be a leftover. Copy any
			# user assignments from old to new, then delete the old role.
			_assignments = frappe.get_all(
				"Has Role",
				filters={"role": old_name, "parenttype": "User"},
				fields=["parent"],
				limit_page_length=0,
			)
			for row in _assignments:
				if not frappe.db.exists(
					"Has Role", {"parent": row.parent, "role": new_name}
				):
					try:
						frappe.get_doc(
							{
								"doctype": "Has Role",
								"parent": row.parent,
								"parenttype": "User",
								"parentfield": "roles",
								"role": new_name,
							}
						).insert(ignore_permissions=True)
					except Exception:
						pass
			frappe.db.delete("Role", old_name)
		else:
			frappe.db.set_value("Role", old_name, "role_name", new_name)

	frappe.db.commit()


def ensure_desk_navigation():
	from adx_secure_qr_login.desktop import (
		ensure_audit_analysis_link,
		ensure_dashboard_link,
		ensure_devices_link,
		ensure_my_qr_link,
	)

	ensure_dashboard_link()
	ensure_devices_link()
	ensure_my_qr_link()
	ensure_audit_analysis_link()


def before_uninstall():
	# Leave Roles, DocTypes and audit history in place. Uninstalling an app on a
	# site that holds security history must not silently destroy the evidence.
	frappe.db.commit()


def create_roles():
	"""Create the QR roles if absent. Safe to call repeatedly."""
	for role in ROLES:
		if frappe.db.exists("Role", role):
			continue
		doc = frappe.get_doc({"doctype": "Role", "role_name": role, "desk_access": 1})
		doc.flags.ignore_permissions = True
		doc.insert(ignore_permissions=True)


def seed_settings():
	"""Create the QR Security Settings single so defaults are materialised once."""
	if frappe.db.exists("DocType", "QR Security Settings"):
		doc = frappe.get_single("QR Security Settings")
		doc.flags.ignore_permissions = True
		doc.flags.ignore_mandatory = True
		doc.save()


def add_roles_to_administrator():
	"""Grant the QR roles to Administrator.

	Mirrors frappe/utils/install.py:41, which grants every role to Administrator.
	Needed so the app is administrable out of the box. Note that both
	`frappe.only_for` and `frappe.has_permission` short-circuit for Administrator,
	so this grant does not weaken the non-Administrator permission tests.
	"""
	if not frappe.db.exists("User", "Administrator"):
		return
	user = frappe.get_doc("User", "Administrator")
	missing = [r for r in QR_ROLES if r not in {row.role for row in user.get("roles") or []}]
	if missing:
		user.flags.ignore_permissions = True
		user.add_roles(*missing)
