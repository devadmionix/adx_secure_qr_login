"""Apply DocType defaults to QR Security Settings fields that were never stored.

A Single's `default` only applies when its row is first created. Settings added
in later versions are therefore absent from `tabSingles` on an upgraded site and
read as 0 -- e.g. `device_tracking` (default 1) silently stayed off, so no QR
Login Device row was ever written.

Only fields with *no stored value at all* are touched. An administrator's
explicit choice, including an explicit 0, is stored as a row and is never
overwritten.
"""

import frappe

SETTINGS = "QR Security Settings"


def execute():
	if not frappe.db.exists("DocType", SETTINGS):
		return

	stored = {
		r[0]
		for r in frappe.db.sql(
			"select field from tabSingles where doctype = %s", (SETTINGS,)
		)
	}

	missing = {}
	for df in frappe.get_meta(SETTINGS).fields:
		if df.default in (None, "") or df.fieldname in stored:
			continue
		if df.fieldtype in ("Section Break", "Column Break", "Tab Break", "HTML", "Button"):
			continue
		missing[df.fieldname] = df.default

	if not missing:
		return

	frappe.db.set_single_value(SETTINGS, missing)
	frappe.db.commit()
