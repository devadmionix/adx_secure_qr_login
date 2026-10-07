# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Desk navigation wiring for the Secure QR Login module.

Sidebar and workspace layout lives in *site* data, not in the app, so editing
the JSON shipped with the module does not update an existing site -- and Frappe
regenerates `Workspace Sidebar` from the module on every `bench migrate`,
silently dropping anything a one-shot patch added.

So the dashboard link is (re)applied after every migrate rather than once. Both
the patch and `after_migrate` call `ensure_dashboard_link()`, which keeps one
authoritative implementation instead of two that can drift.

Idempotent by construction: it only appends what is missing.
"""

import frappe

WORKSPACE = "Secure QR Login"
DASHBOARD_PAGE = "qr-security-dashboard"
DASHBOARD_LABEL = "QR Security Dashboard"


def ensure_dashboard_link() -> bool:
	"""Ensure the QR Security Dashboard page is linked in the desk sidebar.

	Returns True when the link is present (whether it was just added or already
	existed). Never raises: a missing navigation shortcut must not fail migrate.
	"""
	if not frappe.db.exists("Page", DASHBOARD_PAGE):
		return False
	if not frappe.db.exists("Workspace Sidebar", WORKSPACE):
		return False

	try:
		sidebar = frappe.get_doc("Workspace Sidebar", WORKSPACE)
		items = list(sidebar.get("items") or [])

		if any(
			i.link_to == DASHBOARD_PAGE and i.link_type == "Page" for i in items
		):
			return True

		# Sit next to the other QR entries rather than at the very end.
		anchor = next(
			(
				idx
				for idx, i in enumerate(items)
				if i.link_to == "QR Security Settings" and i.link_type == "DocType"
			),
			len(items) - 1,
		)
		items.insert(
			anchor + 1,
			{
				"label": DASHBOARD_LABEL,
				"type": "Link",
				"link_type": "Page",
				"link_to": DASHBOARD_PAGE,
				"icon": "dashboard",
			},
		)

		sidebar.set("items", [])
		for row in items:
			sidebar.append("items", row)

		sidebar.flags.ignore_permissions = True
		sidebar.save(ignore_permissions=True)
		return True
	except Exception:
		frappe.log_error(
			title="QR sidebar link failed",
			message=frappe.get_traceback(),
		)
		return False

DEVICE_DOCTYPE = "QR Login Device"
DEVICE_LABEL = "Devices & Sessions"


def ensure_devices_link() -> bool:
	"""Expose QR Login Device as "Devices & Sessions" in the workspace and sidebar.

	Same contract as `ensure_dashboard_link`: idempotent, re-applied after every
	migrate, never raises. Places the entry right after Login Audit so the menu
	reads Credentials -> Audit -> Devices & Sessions.
	"""
	if not frappe.db.exists("DocType", DEVICE_DOCTYPE):
		return False

	ok = False
	try:
		ok = _ensure_devices_in_workspace() or ok
	except Exception:
		frappe.log_error(
			title="QR devices workspace link failed", message=frappe.get_traceback()
		)
	try:
		ok = _ensure_devices_in_sidebar() or ok
	except Exception:
		frappe.log_error(
			title="QR devices sidebar link failed", message=frappe.get_traceback()
		)
	return ok


def _ensure_devices_in_workspace() -> bool:
	if not frappe.db.exists("Workspace", WORKSPACE):
		return False

	workspace = frappe.get_doc("Workspace", WORKSPACE)
	changed = False

	if not any(s.link_to == DEVICE_DOCTYPE for s in workspace.get("shortcuts") or []):
		workspace.append(
			"shortcuts",
			{
				"color": "Purple",
				"doc_view": "List",
				"label": DEVICE_LABEL,
				"link_to": DEVICE_DOCTYPE,
				"type": "DocType",
			},
		)
		changed = True

	if not any(l.link_to == DEVICE_DOCTYPE for l in workspace.get("links") or []):
		workspace.append(
			"links",
			{
				"hidden": 0,
				"is_query_report": 0,
				"label": DEVICE_LABEL,
				"link_count": 0,
				"link_to": DEVICE_DOCTYPE,
				"link_type": "DocType",
				"onboard": 0,
				"type": "Link",
			},
		)
		changed = True

	try:
		blocks = frappe.parse_json(workspace.content or "[]")
	except Exception:
		blocks = []

	if not any(b.get("data", {}).get("shortcut_name") == DEVICE_LABEL for b in blocks):
		block = {
			"id": "qrScDev0",
			"type": "shortcut",
			"data": {"shortcut_name": DEVICE_LABEL, "col": 4},
		}
		anchor = next(
			(
				i
				for i, b in enumerate(blocks)
				if b.get("data", {}).get("shortcut_name") == "QR Login Audit"
			),
			None,
		)
		if anchor is None:
			blocks.append(block)
		else:
			blocks.insert(anchor + 1, block)
		workspace.content = frappe.as_json(blocks)
		changed = True

	if changed:
		workspace.flags.ignore_permissions = True
		workspace.save(ignore_permissions=True)
	return True


def _ensure_devices_in_sidebar() -> bool:
	if not frappe.db.exists("Workspace Sidebar", WORKSPACE):
		return False

	sidebar = frappe.get_doc("Workspace Sidebar", WORKSPACE)
	items = [i.as_dict() for i in sidebar.get("items") or []]

	if any(i.get("link_to") == DEVICE_DOCTYPE and i.get("link_type") == "DocType" for i in items):
		return True

	anchor = next(
		(
			idx
			for idx, i in enumerate(items)
			if i.get("link_to") == "QR Login Audit" and i.get("link_type") == "DocType"
		),
		len(items) - 1,
	)
	items.insert(
		anchor + 1,
		{
			"label": DEVICE_LABEL,
			"type": "Link",
			"link_type": "DocType",
			"link_to": DEVICE_DOCTYPE,
			"icon": "monitor",
		},
	)

	sidebar.set("items", [])
	for row in items:
		for key in ("name", "idx", "parent", "parenttype", "parentfield", "doctype", "creation", "modified", "modified_by", "owner", "docstatus"):
			row.pop(key, None)
		sidebar.append("items", row)

	sidebar.flags.ignore_permissions = True
	sidebar.save(ignore_permissions=True)
	return True


MY_QR_PAGE = "my-qr"
MY_QR_LABEL = "My QR"


def ensure_my_qr_link() -> bool:
	"""Expose the self-service "My QR" page in the workspace and sidebar.

	Same contract as the other helpers: idempotent, re-applied after every
	migrate, never raises.
	"""
	if not frappe.db.exists("Page", MY_QR_PAGE):
		return False

	ok = False
	try:
		if frappe.db.exists("Workspace", WORKSPACE):
			workspace = frappe.get_doc("Workspace", WORKSPACE)
			changed = False

			if not any(
				s.link_to == MY_QR_PAGE and s.type == "Page"
				for s in workspace.get("shortcuts") or []
			):
				workspace.append(
					"shortcuts",
					{"color": "Cyan", "label": MY_QR_LABEL, "link_to": MY_QR_PAGE, "type": "Page"},
				)
				changed = True

			try:
				blocks = frappe.parse_json(workspace.content or "[]")
			except Exception:
				blocks = []
			if not any(b.get("data", {}).get("shortcut_name") == MY_QR_LABEL for b in blocks):
				block = {
					"id": "qrScMyQr0",
					"type": "shortcut",
					"data": {"shortcut_name": MY_QR_LABEL, "col": 4},
				}
				anchor = next(
					(
						i
						for i, b in enumerate(blocks)
						if b.get("data", {}).get("shortcut_name") == DEVICE_LABEL
					),
					None,
				)
				blocks.insert(anchor + 1, block) if anchor is not None else blocks.append(block)
				workspace.content = frappe.as_json(blocks)
				changed = True

			if changed:
				workspace.flags.ignore_permissions = True
				workspace.save(ignore_permissions=True)
			ok = True
	except Exception:
		frappe.log_error(title="My QR workspace link failed", message=frappe.get_traceback())

	try:
		if frappe.db.exists("Workspace Sidebar", WORKSPACE):
			sidebar = frappe.get_doc("Workspace Sidebar", WORKSPACE)
			items = [i.as_dict() for i in sidebar.get("items") or []]
			if not any(
				i.get("link_to") == MY_QR_PAGE and i.get("link_type") == "Page" for i in items
			):
				anchor = next(
					(
						idx
						for idx, i in enumerate(items)
						if i.get("link_to") == DEVICE_DOCTYPE and i.get("link_type") == "DocType"
					),
					len(items) - 1,
				)
				items.insert(
					anchor + 1,
					{
						"label": MY_QR_LABEL,
						"type": "Link",
						"link_type": "Page",
						"link_to": MY_QR_PAGE,
						"icon": "qr-code",
					},
				)
				sidebar.set("items", [])
				for row in items:
					for key in (
						"name", "idx", "parent", "parenttype", "parentfield",
						"doctype", "creation", "modified", "modified_by", "owner", "docstatus",
					):
						row.pop(key, None)
					sidebar.append("items", row)
				sidebar.flags.ignore_permissions = True
				sidebar.save(ignore_permissions=True)
			ok = True
	except Exception:
		frappe.log_error(title="My QR sidebar link failed", message=frappe.get_traceback())

	return ok


AUDIT_REPORT = "QR Login Audit Analysis"


def ensure_audit_analysis_link() -> bool:
	"""Expose the QR Login Audit Analysis report under Reports in workspace and sidebar.

	Same contract as the other helpers: idempotent, re-applied after every
	migrate, never raises.
	"""
	if not frappe.db.exists("Report", AUDIT_REPORT):
		return False

	ok = False
	try:
		if frappe.db.exists("Workspace", WORKSPACE):
			workspace = frappe.get_doc("Workspace", WORKSPACE)
			changed = False

			if not any(
				s.link_to == AUDIT_REPORT and s.type == "Report"
				for s in workspace.get("shortcuts") or []
			):
				workspace.append(
					"shortcuts",
					{
						"color": "Red",
						"doc_view": "Report",
						"label": AUDIT_REPORT,
						"link_to": AUDIT_REPORT,
						"type": "Report",
					},
				)
				changed = True

			if not any(
				l.link_to == AUDIT_REPORT and l.link_type == "Report"
				for l in workspace.get("links") or []
			):
				workspace.append(
					"links",
					{
						"hidden": 0,
						"is_query_report": 1,
						"label": AUDIT_REPORT,
						"link_count": 0,
						"link_to": AUDIT_REPORT,
						"link_type": "Report",
						"onboard": 0,
						"type": "Link",
					},
				)
				changed = True

			try:
				blocks = frappe.parse_json(workspace.content or "[]")
			except Exception:
				blocks = []
			if not any(b.get("data", {}).get("shortcut_name") == AUDIT_REPORT for b in blocks):
				block = {
					"id": "qrScAudRpt",
					"type": "shortcut",
					"data": {"shortcut_name": AUDIT_REPORT, "col": 4},
				}
				anchor = next(
					(
						i
						for i, b in enumerate(blocks)
						if b.get("data", {}).get("shortcut_name") == "Weekly Security Report"
					),
					None,
				)
				blocks.insert(anchor + 1, block) if anchor is not None else blocks.append(block)
				workspace.content = frappe.as_json(blocks)
				changed = True

			if changed:
				workspace.flags.ignore_permissions = True
				workspace.save(ignore_permissions=True)
			ok = True
	except Exception:
		frappe.log_error(title="Audit analysis workspace link failed", message=frappe.get_traceback())

	try:
		if frappe.db.exists("Workspace Sidebar", WORKSPACE):
			sidebar = frappe.get_doc("Workspace Sidebar", WORKSPACE)
			items = [i.as_dict() for i in sidebar.get("items") or []]
			if not any(
				i.get("link_to") == AUDIT_REPORT and i.get("link_type") == "Report" for i in items
			):
				anchor = next(
					(
						idx
						for idx, i in enumerate(items)
						if i.get("link_to") == "Weekly Security Report"
						and i.get("link_type") == "Report"
					),
					len(items) - 1,
				)
				items.insert(
					anchor + 1,
					{
						"label": AUDIT_REPORT,
						"type": "Link",
						"link_type": "Report",
						"link_to": AUDIT_REPORT,
						"icon": "table",
						"child": 1,
					},
				)
				sidebar.set("items", [])
				for row in items:
					for key in (
						"name", "idx", "parent", "parenttype", "parentfield",
						"doctype", "creation", "modified", "modified_by", "owner", "docstatus",
					):
						row.pop(key, None)
					sidebar.append("items", row)
				sidebar.flags.ignore_permissions = True
				sidebar.save(ignore_permissions=True)
			ok = True
	except Exception:
		frappe.log_error(title="Audit analysis sidebar link failed", message=frappe.get_traceback())

	return ok


AUDIT_DOCTYPE = "QR Login Audit"
AUDIT_LABEL = "QR Login Audit"
# A hand-made Page used to be wired in here; it had no working controller, so the
# sidebar entry did nothing when clicked. Any link to it is repaired below.
_STALE_AUDIT_PAGES = ("qr-login-audit", "qr_login_audit")
_ROW_META = (
	"name", "idx", "parent", "parenttype", "parentfield",
	"doctype", "creation", "modified", "modified_by", "owner", "docstatus",
)


def ensure_audit_link() -> bool:
	"""Make "QR Login Audit" open the audit DocType list from the sidebar.

	Same contract as the other helpers: idempotent, re-applied after every
	migrate, never raises. It also repairs sites that already hold a broken link
	to the removed `qr-login-audit` Page, and deletes that orphan Page record.
	"""
	if not frappe.db.exists("DocType", AUDIT_DOCTYPE):
		return False

	ok = False
	try:
		for page in _STALE_AUDIT_PAGES:
			if frappe.db.exists("Page", page):
				frappe.delete_doc("Page", page, ignore_permissions=True, force=True)

		if frappe.db.exists("Workspace", WORKSPACE):
			workspace = frappe.get_doc("Workspace", WORKSPACE)
			changed = False
			for row in workspace.get("shortcuts") or []:
				if row.label == AUDIT_LABEL and (
					row.type != "DocType" or row.link_to != AUDIT_DOCTYPE
				):
					row.type, row.link_to, row.doc_view = "DocType", AUDIT_DOCTYPE, "List"
					changed = True
			if not any(
				s.link_to == AUDIT_DOCTYPE and s.type == "DocType"
				for s in workspace.get("shortcuts") or []
			):
				workspace.append(
					"shortcuts",
					{
						"color": "Green",
						"doc_view": "List",
						"label": AUDIT_LABEL,
						"link_to": AUDIT_DOCTYPE,
						"type": "DocType",
					},
				)
				changed = True
			if changed:
				workspace.flags.ignore_permissions = True
				workspace.save(ignore_permissions=True)
			ok = True
	except Exception:
		frappe.log_error(title="QR audit workspace link failed", message=frappe.get_traceback())

	try:
		if frappe.db.exists("Workspace Sidebar", WORKSPACE):
			sidebar = frappe.get_doc("Workspace Sidebar", WORKSPACE)
			items = [i.as_dict() for i in sidebar.get("items") or []]
			changed = False
			found = False
			for i in items:
				if i.get("label") == AUDIT_LABEL or i.get("link_to") in _STALE_AUDIT_PAGES:
					found = True
					if i.get("link_type") != "DocType" or i.get("link_to") != AUDIT_DOCTYPE:
						i["link_type"], i["link_to"] = "DocType", AUDIT_DOCTYPE
						changed = True
				elif i.get("link_to") == AUDIT_DOCTYPE and i.get("link_type") == "DocType":
					found = True
			if not found:
				anchor = next(
					(
						idx
						for idx, i in enumerate(items)
						if i.get("link_to") == "QR Login Credential"
						and i.get("link_type") == "DocType"
					),
					len(items) - 1,
				)
				items.insert(
					anchor + 1,
					{
						"label": AUDIT_LABEL,
						"type": "Link",
						"link_type": "DocType",
						"link_to": AUDIT_DOCTYPE,
						"icon": "list",
					},
				)
				changed = True
			if changed:
				sidebar.set("items", [])
				for row in items:
					for key in _ROW_META:
						row.pop(key, None)
					sidebar.append("items", row)
				sidebar.flags.ignore_permissions = True
				sidebar.save(ignore_permissions=True)
			ok = True
	except Exception:
		frappe.log_error(title="QR audit sidebar link failed", message=frappe.get_traceback())

	return ok
