# Copyright (c) 2026, ADmionix Solutions
# License: MIT

import os

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
	# No explicit commit: `frappe.installer.install_app` commits the whole
	# installation transaction itself (frappe/installer.py:389).
	create_roles()
	seed_settings()
	add_roles_to_administrator()
	ensure_desk_navigation()


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

	# No explicit commit: this runs from the `after_migrate` hook, and `bench
	# migrate` commits the migration transaction itself. Committing half way
	# through would make a later failure impossible to roll back.
	_prune_stale_role_references()


def _prune_stale_role_references():
	"""Repair child rows that store a role *name* and so survive a Role rename.

	Frappe stores role names as plain strings in several child tables. Renaming the
	`Role` document updates none of them, leaving rows that name a role which no
	longer exists. Two of those silently break access:

	1. `Custom DocPerm` -- `Meta.set_custom_permissions()` (frappe/model/meta.py:640)
	   replaces a DocType's permissions *entirely* with matching rows, so one stale
	   row naming "QR Admin" masks the DocType JSON: `get_role_permissions()`
	   matches nothing, `read` becomes 0, and every QR Admin/Manager is refused on
	   that DocType with no visible cause.

	2. `Has Role` on a Page -- `Page.is_permitted()` compares these against the
	   session user's roles, so a stale "QR Admin" entry hides the dashboard from
	   the very users who should see it.

	Rows whose role is a known pre-rename name are *rewritten* to the current
	name, which restores the access the row was meant to grant. Anything naming a
	role that neither exists now nor was a legacy QR name is dropped.
	"""
	rename_map = {
		LEGACY_ROLE_ADMIN: ROLE_ADMIN,
		LEGACY_ROLE_MANAGER: ROLE_MANAGER,
	}

	for doctype in ("Custom DocPerm", "Has Role"):
		for row in frappe.get_all(
			doctype,
			fields=["name", "role"],
			limit_page_length=0,
			ignore_permissions=True,
		):
			if frappe.db.exists("Role", row.role):
				continue
			new_role = rename_map.get(row.role)
			if new_role and not frappe.db.exists(
				doctype, {"name": row.name, "role": new_role}
			):
				frappe.db.set_value(doctype, row.name, "role", new_role)
			else:
				frappe.db.delete(doctype, row.name)

	_repoint_role_link_fields(rename_map)
	_sync_page_roles_from_json()


def _repoint_role_link_fields(rename_map: dict) -> None:
	"""Rewrite Link-to-Role fields that still hold a pre-rename role name.

	`Document._validate_links()` (frappe/model/document.py:1221) refuses to save a
	document whose Link field names a row that does not exist. A settings field
	left pointing at "QR Admin" therefore makes the whole QR Security Settings
	single unsaveable, which breaks every page that writes to it -- with a
	`LinkValidationError` that says nothing about roles.
	"""
	for meta in frappe.get_all(
		"DocField",
		filters={"fieldtype": "Link", "options": "Role"},
		fields=["parent", "fieldname"],
		limit_page_length=0,
		ignore_permissions=True,
	):
		doctype, fieldname = meta.parent, meta.fieldname
		if not frappe.db.exists("DocType", doctype):
			continue

		if frappe.get_meta(doctype).issingle:
			# Singles live in tabSingles keyed by field, not in their own table.
			stored = frappe.db.get_single_value(doctype, fieldname)
			if stored in rename_map:
				frappe.db.set_single_value(
					doctype, fieldname, rename_map[stored], update_modified=False
				)
			continue

		if not frappe.db.table_exists(doctype):
			continue

		stored = frappe.db.get_value(doctype, "name", fieldname)
		if stored in rename_map:
			frappe.db.set_value(
				doctype, "name", fieldname, rename_map[stored], update_modified=False
			)


def _page_json_path(app_path: str, folder: str, slug: str) -> str | None:
	"""Resolve a Page/Report JSON shipped with this app, or None if unsafe/absent.

	`folder` and `slug` are build-time literals from `adx_secure_qr_login.desktop`,
	never request input, but the path is still verified: `realpath` resolves
	symlinks and `..` segments, and the result must stay under the app directory.
	That closes the traversal risk structurally rather than by trusting the
	callers.
	"""
	root = os.path.realpath(app_path)
	candidate = os.path.realpath(
		os.path.join(root, "secure_qr_login", folder, slug, f"{slug}.json")
	)
	if os.path.commonpath([root, candidate]) != root:
		return None
	return candidate if os.path.isfile(candidate) else None


def _sync_page_roles_from_json():
	"""Ensure each app Page's and Report's `Has Role` rows match its DocType JSON.

	The JSON is the source of truth for which roles may open a page or run a
	report, but Frappe does not re-sync child rows of an *already existing*
	document on migrate. A document whose role rows were dropped, or left over
	from before the role rename, therefore keeps serving the stale set.

	Reports are the sharper edge of this. `DeskViews._build_user_pages_or_reports`
	treats a page or report with **no** role rows as allowed to everyone
	(frappe/desk/desk_views.py:229, "pages and reports with no role are allowed"),
	and `is_item_allowed` gates sidebar visibility on that set. So a report that
	should be admin-only but lost its role rows does not merely lose access -- it
	gains it, and shows up in the sidebar of every user. This syncs Reports as
	well as Pages so both directions are repaired.
	"""
	import json

	from adx_secure_qr_login.desktop import (
		AUDIT_REPORT,
		DASHBOARD_PAGE,
		MY_QR_PAGE,
		WEEKLY_REPORT,
	)

	app_path = frappe.get_app_path("adx_secure_qr_login")
	targets = (
		*(("Page", name, "page") for name in (DASHBOARD_PAGE, MY_QR_PAGE)),
		*(("Report", name, "report") for name in (WEEKLY_REPORT, AUDIT_REPORT)),
	)

	for parenttype, name, folder in targets:
		slug = frappe.scrub(name)
		path = _page_json_path(app_path, folder, slug)
		if not (frappe.db.exists(parenttype, name) and path is not None):
			continue

		with open(path) as f:  # nosemgrep: frappe-security-file-traversal
			# `path` is built by _page_json_path, which proves the resolved file
			# lives inside this app's own directory before returning it.
			expected = {r["role"] for r in json.load(f).get("roles") or [] if r.get("role")}
		current = set(
			frappe.get_all(
				"Has Role",
				filters={"parent": name, "parenttype": parenttype},
				pluck="role",
				ignore_permissions=True,
			)
		)

		for role in sorted(expected - current):
			frappe.get_doc(
				{
					"doctype": "Has Role",
					"parent": name,
					"parenttype": parenttype,
					"parentfield": "roles",
					"role": role,
				}
			).insert(ignore_permissions=True)
		for role in sorted(current - expected):
			row = frappe.db.get_value(
				"Has Role",
				{"parent": name, "parenttype": parenttype, "role": role},
				"name",
			)
			if row:
				frappe.db.delete("Has Role", row)


def ensure_desk_navigation():
	from adx_secure_qr_login.desktop import (
		apply_sidebar_layout,
		ensure_audit_link,
		ensure_audit_analysis_link,
		ensure_dashboard_link,
		ensure_devices_link,
		ensure_my_qr_link,
		repair_workspace_link_types,
	)

	# Runs first: a link row with no link_type makes the whole workspace raise
	# on render, which would mask every repair below.
	repair_workspace_link_types()
	ensure_audit_link()
	ensure_dashboard_link()
	ensure_devices_link()
	ensure_my_qr_link()
	ensure_audit_analysis_link()
	# Runs last on purpose: the helpers above only append single entries and so
	# cannot express grouping or order. This pass rewrites the sidebar rows to
	# the canonical layout, undoing any position they got wrong.
	apply_sidebar_layout()


def before_uninstall():
	# Leave Roles, DocTypes and audit history in place. Uninstalling an app on a
	# site that holds security history must not silently destroy the evidence.
	#
	# This hook is not registered in hooks.py (the real teardown work lives in
	# uninstall.py) and deliberately writes nothing, so there is nothing to
	# commit: `frappe.installer.uninstall_app` commits the uninstall transaction
	# itself.
	pass


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

