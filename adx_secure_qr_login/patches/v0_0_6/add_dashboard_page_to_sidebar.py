"""Link the QR Security Dashboard page into the desk sidebar.

The explicit "Secure QR Login" sidebar (v0_0_5) replaces Frappe's
auto-generated one, so the new Page needs an explicit link or it is
reachable only by URL/search. Idempotent.
"""

import frappe

WORKSPACE = "Secure QR Login"
PAGE = "qr-security-dashboard"
LABEL = "QR Security Dashboard"


def execute():
	if not frappe.db.exists("Page", PAGE):
		return
	if not frappe.db.exists("Workspace Sidebar", WORKSPACE):
		return

	sidebar = frappe.get_doc("Workspace Sidebar", WORKSPACE)
	pairs = [(i.link_to, i.link_type) for i in sidebar.get("items") or []]
	if (PAGE, "Page") in pairs:
		return

	items = list(sidebar.get("items") or [])
	anchor = next(
		(
			idx
			for idx, i in enumerate(items)
			if i.link_to == "QR Security Settings" and i.link_type == "DocType"
		),
		len(items),
	)

	row = sidebar.append(
		"items",
		{
			"label": LABEL,
			"type": "Link",
			"link_type": "Page",
			"link_to": PAGE,
			"icon": "dashboard",
		},
	)
	# `append` puts the row last; move it next to the other QR entries.
	ordered = [r for r in sidebar.get("items") if r is not row]
	ordered.insert(min(anchor + 1, len(ordered)), row)
	sidebar.set("items", [])
	for r in ordered:
		sidebar.append("items", r.as_dict())

	sidebar.flags.ignore_permissions = True
	sidebar.save(ignore_permissions=True)
	frappe.db.commit()
