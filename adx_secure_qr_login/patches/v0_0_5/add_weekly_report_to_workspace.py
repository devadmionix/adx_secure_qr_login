"""Link Weekly Security Report into the Secure QR Login workspace.

Workspace layout lives in site data, so editing the workspace JSON alone does
not update existing sites. This patch appends the shortcut/link (and a
"Reports" header) the same way v0_0_3 attaches the dashboard chart.
Idempotent: re-running never duplicates entries.
"""

import frappe

WORKSPACE = "Secure QR Login"
LABEL = "Weekly Security Report"

# Frappe auto-generates the desk sidebar from the module but caps it at the
# first 3 doctypes, which silently drops this report. An explicit
# Workspace Sidebar record takes precedence over the auto-generated one and
# lists all four entries.
SIDEBAR_ITEMS = [
	"QR Login Credential",
	"QR Login Audit",
	"QR Security Settings",
	"Weekly Security Report",
]


def execute():
	if not frappe.db.exists("DocType", LABEL):
		return
	if not frappe.db.exists("Workspace", WORKSPACE):
		return

	workspace = frappe.get_doc("Workspace", WORKSPACE)

	if not any(s.label == LABEL for s in workspace.get("shortcuts") or []):
		workspace.append(
			"shortcuts",
			{
				"color": "Orange",
				"doc_view": "List",
				"label": LABEL,
				"link_to": LABEL,
				"type": "DocType",
			},
		)

	if not any(
		(link.label == LABEL and link.link_to == LABEL)
		for link in workspace.get("links") or []
	):
		workspace.append(
			"links",
			{
				"hidden": 0,
				"is_query_report": 0,
				"label": LABEL,
				"link_count": 0,
				"link_to": LABEL,
				"link_type": "DocType",
				"onboard": 0,
				"type": "Link",
			},
		)

	try:
		blocks = frappe.parse_json(workspace.content or "[]")
	except Exception:
		blocks = []

	if not any(
		block.get("data", {}).get("shortcut_name") == LABEL for block in blocks
	):
		blocks.append(
			{
				"id": "qrHeadRpt",
				"type": "header",
				"data": {"text": '<span class="h4"><b>Reports</b></span>', "col": 12},
			}
		)
		blocks.append(
			{
				"id": "qrScRpt0",
				"type": "shortcut",
				"data": {"shortcut_name": LABEL, "col": 4},
			}
		)
		workspace.content = frappe.as_json(blocks)

	workspace.flags.ignore_permissions = True
	workspace.save(ignore_permissions=True)

	_ensure_sidebar()
	frappe.db.commit()


def _ensure_sidebar():
	"""Explicit sidebar so all four doctypes appear (auto-gen caps at 3)."""
	if frappe.db.exists("Workspace Sidebar", WORKSPACE):
		sidebar = frappe.get_doc("Workspace Sidebar", WORKSPACE)
		pairs = [
			(item.link_to, item.link_type) for item in sidebar.get("items") or []
		]
		if all((name, "DocType") in pairs for name in SIDEBAR_ITEMS) and (
			not frappe.db.exists("Report", LABEL) or (LABEL, "Report") in pairs
		):
			return
	else:
		sidebar = frappe.new_doc("Workspace Sidebar")
		sidebar.title = WORKSPACE
		sidebar.module = WORKSPACE

	sidebar.set("items", [])
	section_added = False
	for name in SIDEBAR_ITEMS:
		if not frappe.db.exists("DocType", name):
			continue
		row = {"label": name, "type": "Link", "link_type": "DocType", "link_to": name}
		if "settings" in name.lower():
			row["icon"] = "settings"
		sidebar.append("items", row)

	# Graphical, filterable report (script report with chart + summary cards).
	if frappe.db.exists("Report", LABEL):
		sidebar.append(
			"items", {"label": "Reports", "type": "Section Break", "link_type": "", "link_to": ""}
		)
		sidebar.append(
			"items",
			{
				"label": LABEL,
				"type": "Link",
				"link_type": "Report",
				"link_to": LABEL,
				"icon": "table",
				"child": 1,
			},
		)
		section_added = True

	sidebar.flags.ignore_permissions = True
	sidebar.save(ignore_permissions=True)
