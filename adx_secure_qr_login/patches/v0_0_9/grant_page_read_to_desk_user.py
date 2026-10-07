"""Grant Desk User read access to the Page doctype.

Normal ERPNext users need this to view any custom page (e.g. "My QR") and
to render the Secure QR Login workspace. Without it they get:
  "User X does not have doctype access via role permission for document Page"
"""

import frappe


def execute():
	if frappe.db.exists("DocPerm", {"parent": "Page", "role": "Desk User"}):
		return

	frappe.get_doc(
		{
			"doctype": "DocPerm",
			"parent": "Page",
			"parentfield": "permissions",
			"parenttype": "DocType",
			"role": "Desk User",
			"read": 1,
			"write": 0,
			"create": 0,
			"delete": 0,
			"submit": 0,
			"cancel": 0,
			"amend": 0,
			"report": 0,
			"export": 0,
			"import": 0,
			"share": 0,
			"print": 0,
			"email": 0,
		}
	).insert(ignore_permissions=True)
	frappe.clear_cache()
