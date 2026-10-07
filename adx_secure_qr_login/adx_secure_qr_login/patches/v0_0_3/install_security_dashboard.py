"""Install the QR Security dashboard chart and link it into the workspace.

Folder-synced `Dashboard Chart` records only reach a module that frappe scans
with `get_doc_files`, which walks a fixed list of doctype folders
(frappe/model/sync.py:150). `dashboard_chart` is not in that list -- frappe's own
charts live under `frappe/core/dashboard_chart` and are handled by a separate
frappe-only branch. An app cannot folder-sync one.

So the chart is created here instead, from a patch. It is idempotent, and an
existing row (edited by an administrator in the desk) is left alone.
"""

import frappe

CHART_NAME = "adx_qr_security"
WORKSPACE = "Secure QR Login"


def execute():
	if not frappe.db.exists("DocType", "QR Login Credential"):
		return

	if not frappe.db.exists("Dashboard Chart", CHART_NAME):
		chart = frappe.get_doc(
			{
				"doctype": "Dashboard Chart",
				"name": CHART_NAME,
				"chart_name": CHART_NAME,
				# `chart_type` is the Select (Count / Sum / ... / Custom / Report);
				# `source` is a separate Link to "Dashboard Chart Source" and must be
				# left empty for a Custom chart. Setting source="Custom" fails link
				# validation -- "Custom" is not a Chart Source record.
				"chart_type": "Custom",
				"type": "Bar",
				# filters_json is reqd=1 on the DocType with no default, so insert
				# fails with MandatoryError unless it is supplied. An empty JSON
				# object is the correct value for a Custom chart, which filters its
				# own data client-side via qr_dashboard.js.
				"filters_json": "{}",
				# is_standard is deliberately 0, not 1. A standard chart is
				# re-exported to files by on_update() in developer mode
				# (dashboard_chart.py:387-390) and rejected outright by validate()
				# on a production site (line 393). This app ships the chart from a
				# patch rather than a synced folder, so there is nothing to
				# re-export and nothing to protect -- marking it non-standard lets
				# an administrator edit it in the desk if they want a different
				# layout, without the file being regenerated underneath them.
				"is_standard": 0,
				"is_public": 1,
				"module": "Secure QR Login",
				"document_type": "QR Login Credential",
			}
		)
		chart.flags.ignore_permissions = True
		chart.insert(ignore_permissions=True)

	for role in ("QR Login Admin", "QR Login Manager", "QR Admin", "QR Manager"):
		if frappe.db.exists("Role", role) and not frappe.db.exists(
			"Has Role", {"parent": CHART_NAME, "parenttype": "Dashboard Chart", "role": role}
		):
			chart = frappe.get_doc("Dashboard Chart", CHART_NAME)
			chart.append("roles", {"role": role})
			chart.flags.ignore_permissions = True
			chart.save(ignore_permissions=True)

	_attach_to_workspace()
	frappe.db.commit()


def _attach_to_workspace():
	"""Register the chart on the workspace so it renders inside the desk."""
	if not frappe.db.exists("Workspace", WORKSPACE):
		return

	workspace = frappe.get_doc("Workspace", WORKSPACE)

	# `content` holds the layout as a JSON string. Only add the block when the
	# workspace does not already reference this chart, so re-running the patch
	# cannot duplicate it.
	try:
		blocks = frappe.parse_json(workspace.content or "[]")
	except Exception:
		blocks = []

	for block in blocks:
		if block.get("data", {}).get("chart_name") == CHART_NAME:
			return

	blocks.append({"id": "qrDashBlock1", "type": "chart", "data": {"chart_name": CHART_NAME, "col": 12}})
	workspace.content = frappe.as_json(blocks)
	workspace.flags.ignore_permissions = True
	workspace.save(ignore_permissions=True)
