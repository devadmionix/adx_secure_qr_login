"""Backfill `weekly_report_hour` on existing sites.

The field's DocType `default` (8) only applies when the Single row is first
inserted. On an upgraded site the value is absent and reads as 0, which would
send the weekly report at midnight instead of the intended 08:00.
"""

import frappe

SETTINGS = "QR Security Settings"


def execute():
	if not frappe.db.exists("DocType", SETTINGS):
		return

	current = frappe.db.get_singles_dict(SETTINGS)
	if not current:
		return

	# Only an unset value is touched; an explicit hour (even 0) is kept.
	if current.get("weekly_report_hour") in (None, ""):
		frappe.db.set_single_value(SETTINGS, "weekly_report_hour", 8)
		frappe.db.commit()
