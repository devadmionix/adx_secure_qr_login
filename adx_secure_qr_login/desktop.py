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