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


AUDIT_REPORT = "QR Login Audit Analysis"
AUDIT_DOCTYPE = "QR Login Audit"
AUDIT_LABEL = "QR Login Audit"

_LINK_TYPES = {"DocType", "Page", "Report", "Workspace", "Dashboard", "URL"}


def repair_workspace_link_types() -> bool:
	"""Give every workspace link a `link_type`, or the workspace fails to render.

	`Workspace.get_links()` (frappe/desk/desktop.py:213) calls
	`DeskViews.is_item_allowed(item.link_to, item.link_type)`, which calls
	`item_type.lower()` with no guard. One link row missing `link_type` therefore
	raises `AttributeError: 'NoneType' object has no attribute 'lower'` and the
	whole workspace renders blank -- for every user, including Administrator, with
	no hint about which link is at fault.

	Derived from the target's own doctype where possible, and from the label for
	the rest. Card Breaks are pure separators and carry a harmless default.
	"""
	if not frappe.db.exists("Workspace", WORKSPACE):
		return False

	try:
		workspace = frappe.get_doc("Workspace", WORKSPACE)
		changed = False

		for link in workspace.get("links") or []:
			if link.get("link_type") in _LINK_TYPES:
				continue

			if link.get("type") == "Card Break" or not link.get("link_to"):
				link.link_type = "DocType"
			elif frappe.db.exists("Page", link.link_to):
				link.link_type = "Page"
			elif frappe.db.exists("Report", link.link_to):
				link.link_type = "Report"
			elif frappe.db.exists("DocType", link.link_to):
				link.link_type = "DocType"
			else:
				link.link_type = "DocType"

			changed = True

		if changed:
			workspace.flags.ignore_permissions = True
			workspace.save(ignore_permissions=True)
		return True
	except Exception:
		frappe.log_error(
			title="QR workspace link_type repair failed", message=frappe.get_traceback()
		)
		return False

_STALE_AUDIT_PAGES = frozenset({"qr-login-audit"})

def ensure_audit_link() -> bool:
	"""Ensure 'QR Login Audit' sidebar/workspace links point to the DocType."""
	ok = False
	try:
		if not frappe.db.exists("DocType", AUDIT_DOCTYPE):
			return False
		if frappe.db.exists("Workspace Sidebar", WORKSPACE):
			sidebar = frappe.get_doc("Workspace Sidebar", WORKSPACE)
			items = [i.as_dict() for i in sidebar.get("items") or []]
			items = [i for i in items if not (i.get("label") == AUDIT_LABEL and i.get("link_type") == "Page")]
			if not any(i.get("label") == AUDIT_LABEL and i.get("link_to") == AUDIT_DOCTYPE and i.get("link_type") == "DocType" for i in items):
				anchor = next((idx for idx, i in enumerate(items) if i.get("link_to") == "QR Login Credential" and i.get("link_type") == "DocType"), len(items) - 1)
				items.insert(anchor + 1, {"label": AUDIT_LABEL, "type": "Link", "link_type": "DocType", "link_to": AUDIT_DOCTYPE, "icon": "table"})
			sidebar.set("items", [])
			for row in items:
				for key in ("name", "idx", "parent", "parenttype", "parentfield", "doctype", "creation", "modified", "modified_by", "owner", "docstatus"):
					row.pop(key, None)
			sidebar.append("items", row)
			sidebar.flags.ignore_permissions = True
			sidebar.save(ignore_permissions=True)
			ok = True
		if frappe.db.exists("Workspace", WORKSPACE):
			workspace = frappe.get_doc("Workspace", WORKSPACE)
			changed = False
			for s in workspace.get("shortcuts") or []:
				if s.get("label") == AUDIT_LABEL:
					if s.get("link_to") != AUDIT_DOCTYPE or s.get("type") != "DocType":
						s.link_to = AUDIT_DOCTYPE
						s.type = "DocType"
						s.doc_view = "List"
						changed = True
			if changed:
				workspace.flags.ignore_permissions = True
				workspace.save(ignore_permissions=True)
			ok = True
	except Exception:
		frappe.log_error(title="QR audit link failed", message=frappe.get_traceback())
	return ok


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


# ---------------------------------------------------------------------------
# Canonical sidebar layout
# ---------------------------------------------------------------------------
# Frappe v16 renders the desk sidebar from the `Workspace Sidebar` doctype, NOT
# from `Workspace.links` -- that field only feeds the legacy workspace editor.
# Editing the shipped `Workspace` JSON therefore has no effect on what a user
# actually sees in the sidebar, and `bench migrate` rebuilds `Workspace Sidebar`
# from the module on every run.
#
# The `ensure_*_link()` helpers above can only *append* one missing entry each,
# which cannot express grouping or ordering: `ensure_dashboard_link()` in
# particular anchors on "QR Security Settings" and so would push the dashboard
# back to the top level. The order is therefore declared once, here, and
# re-applied after install and after every migrate. `ensure_desk_navigation()`
# calls this last, making it the authority for sidebar content and position.
#
# A `Section Break` item is the collapsible group header. Frappe nests every
# following item with `child = 1` under the most recent section break
# (frappe/public/js/frappe/ui/sidebar/sidebar.js, `find_nested_items`), so
# grouping is expressed by ordering plus that flag -- nothing else.

CREDENTIAL_DOCTYPE = "QR Login Credential"
CREDENTIAL_LABEL = "QR Login Credential"
SETTINGS_DOCTYPE = "QR Security Settings"
SETTINGS_LABEL = "QR Security Settings"
WEEKLY_REPORT = "Weekly Security Report"
REPORTS_SECTION_LABEL = "Reports"

SIDEBAR_LAYOUT = (
	{
		"type": "Link", "link_type": "DocType",
		"link_to": CREDENTIAL_DOCTYPE, "label": CREDENTIAL_LABEL, "icon": "key",
	},
	{
		"type": "Link", "link_type": "DocType",
		"link_to": AUDIT_DOCTYPE, "label": AUDIT_LABEL, "icon": "table",
	},
	{
		"type": "Link", "link_type": "DocType",
		"link_to": DEVICE_DOCTYPE, "label": DEVICE_LABEL, "icon": "monitor",
	},
	{
		"type": "Link", "link_type": "Page",
		"link_to": MY_QR_PAGE, "label": MY_QR_LABEL, "icon": "qr-code",
	},
	{
		"type": "Link", "link_type": "DocType",
		"link_to": SETTINGS_DOCTYPE, "label": SETTINGS_LABEL, "icon": "settings",
	},
	{"type": "Section Break", "label": REPORTS_SECTION_LABEL},
	{
		"type": "Link", "link_type": "Report", "child": 1,
		"link_to": WEEKLY_REPORT, "label": WEEKLY_REPORT, "icon": "table",
	},
	{
		"type": "Link", "link_type": "Report", "child": 1,
		"link_to": AUDIT_REPORT, "label": AUDIT_REPORT, "icon": "table",
	},
	{
		"type": "Link", "link_type": "Page", "child": 1,
		"link_to": DASHBOARD_PAGE, "label": DASHBOARD_LABEL, "icon": "dashboard",
	},
)

# Child rows carry Frappe's document bookkeeping, which never appears in the
# layout specs and must be ignored when deciding whether a save is needed.
_LAYOUT_KEYS = frozenset({k for spec in SIDEBAR_LAYOUT for k in spec})


def apply_sidebar_layout() -> bool:
	"""Rewrite the `Workspace Sidebar` items to match `SIDEBAR_LAYOUT`.

	Replaces the rows outright rather than appending, so this both fixes the
	order and repairs a sidebar an older version appended to. It is a no-op
	when the saved rows already match, so an unchanged layout costs no write.

	Never raises: a sidebar that cannot be laid out must not fail migrate.
	Returns True when the sidebar matches the layout afterwards.
	"""
	if not frappe.db.exists("Workspace Sidebar", WORKSPACE):
		return False

	try:
		sidebar = frappe.get_doc("Workspace Sidebar", WORKSPACE)
		if _normalized_items(sidebar) == _expected_items():
			return True

		sidebar.set("items", [])
		for spec in _expected_items():
			sidebar.append("items", dict(spec))
		sidebar.flags.ignore_permissions = True
		sidebar.save(ignore_permissions=True)
		return True
	except Exception:
		frappe.log_error(
			title="QR sidebar layout failed", message=frappe.get_traceback()
		)
		return False


def _expected_items() -> list:
	"""The layout, minus entries whose target does not exist on this site.

	Skipping rather than linking to a missing DocType keeps a partially
	installed site free of dead sidebar entries.
	"""
	items = []
	for spec in SIDEBAR_LAYOUT:
		if spec.get("type") == "Link" and not _link_target_exists(spec):
			continue
		items.append(spec)
	return items


def _link_target_exists(spec: dict) -> bool:
	link_type = spec.get("link_type")
	link_to = spec.get("link_to")
	if link_type in ("DocType", "Report"):
		return bool(frappe.db.exists(link_type, link_to))
	if link_type == "Page":
		return bool(frappe.db.exists("Page", link_to))
	return True


def _normalized_items(sidebar) -> list:
	"""Saved rows reduced to comparable layout fields, empty values dropped."""
	rows = []
	for row in sidebar.get("items") or []:
		rows.append(
			{
				k: row.get(k)
				for k in _LAYOUT_KEYS
				if row.get(k) not in (None, 0, "")
			}
		)
	return rows
