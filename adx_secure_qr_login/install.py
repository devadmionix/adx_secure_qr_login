# Copyright (c) 2026, ADmionix Solutions
# License: MIT

import frappe

from adx_secure_qr_login.secure_qr_login.constants import ROLE_ADMIN, ROLE_MANAGER, QR_ROLES

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
	"""Re-assert desk navigation after every migrate.

	`bench migrate` regenerates `Workspace Sidebar` from the module, which drops
	anything a one-shot patch added. Without this the QR Security Dashboard
	shortcut silently disappears from the sidebar on an upgraded site, leaving it
	reachable only by URL. The helper is idempotent, so calling it on every
	migrate is safe.
	"""
	ensure_desk_navigation()


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
