# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Script Report: QR Login Audit Analysis.

An analysis layer over the existing `QR Login Audit` rows -- nothing is copied or
stored. Without "Group By" it is a filterable detail log (the source for the
Print / PDF audit report); with "Group By" (and optionally "Pivot By") it becomes
a count table. A chart and summary cards are always derived from the same
permission-scoped rows, so they cannot show data the table does not.

Access: QR Admin and QR Manager only (the DocType's own permissions). Row scope
(a manager's users, Company User Permissions) is applied by `frappe.get_list`.
"""

import frappe
from frappe import _

from adx_secure_qr_login.security import audit_analysis as aa


def execute(filters=None):
	filters = frappe._dict(filters or {})

	frappe.has_permission("QR Login Audit", "report", throw=True)

	rows, truncated = aa.fetch_rows(filters)

	group_by = filters.get("group_by")
	pivot_by = filters.get("pivot_by")
	if pivot_by == group_by:
		pivot_by = None

	if group_by:
		columns, data = _grouped(rows, group_by, pivot_by)
	else:
		columns, data = _detail(rows)

	message = None
	if truncated:
		message = _(
			"Only the newest {0} events are included. Narrow the date range for a complete analysis."
		).format(aa.MAX_ROWS)

	return (
		columns,
		data,
		message,
		aa.chart_for(rows, filters.get("chart") or "Successful vs Failed Logins"),
		_summary(rows),
	)


def _detail(rows):
	columns = [
		{"label": _("Time"), "fieldname": "occurred_on", "fieldtype": "Datetime", "width": 160},
		{"label": _("User"), "fieldname": "user", "fieldtype": "Data", "width": 190},
		{"label": _("Company"), "fieldname": "company", "fieldtype": "Data", "width": 130},
		{"label": _("Event"), "fieldname": "event", "fieldtype": "Data", "width": 170},
		{"label": _("Result"), "fieldname": "result", "fieldtype": "Data", "width": 80},
		{"label": _("Reason"), "fieldname": "reason_code", "fieldtype": "Data", "width": 170},
		{"label": _("IP Address"), "fieldname": "ip_address", "fieldtype": "Data", "width": 120},
		{"label": _("Device"), "fieldname": "device", "fieldtype": "Data", "width": 160},
		{"label": _("Session"), "fieldname": "session", "fieldtype": "Data", "width": 130},
	]
	data = [
		{
			"occurred_on": r["occurred_on"],
			"user": r["user"],
			"company": r["company"],
			"event": r["event"],
			"result": aa.result_label(r),
			"reason_code": r["reason_code"],
			"ip_address": r["ip_address"],
			"device": aa.device_label(r),
			# A hashed reference (see session_guard.session_reference), never a sid.
			"session": r["session_reference"],
		}
		for r in rows
	]
	return columns, data


def _grouped(rows, group_by, pivot_by):
	groups, pivots = aa.group(rows, group_by, pivot_by)

	columns = [
		{
			"label": _(group_by),
			"fieldname": "group",
			"fieldtype": "Data",
			"width": 220,
		},
		{"label": _("Total"), "fieldname": "total", "fieldtype": "Int", "width": 90},
	]

	if pivot_by:
		for i, value in enumerate(pivots[:50]):
			columns.append(
				{"label": value, "fieldname": f"pv_{i}", "fieldtype": "Int", "width": 110}
			)
	elif group_by != "Result":
		columns.extend(
			[
				{"label": _("Successful"), "fieldname": "success", "fieldtype": "Int", "width": 100},
				{"label": _("Failed"), "fieldname": "failed", "fieldtype": "Int", "width": 90},
			]
		)

	data = []
	for g in groups:
		row = {"group": g["key"], "total": g["total"], "success": g["success"], "failed": g["failed"]}
		if pivot_by:
			for i, value in enumerate(pivots[:50]):
				row[f"pv_{i}"] = g["cells"].get(value, 0)
		data.append(row)

	return columns, data


def _summary(rows):
	ok = sum(1 for r in rows if aa.is_successful_login(r))
	bad = sum(1 for r in rows if aa.is_failed_login(r))
	security = sum(1 for r in rows if aa.in_category(r, aa.CATEGORY_SECURITY))
	return [
		{"value": len(rows), "label": _("Total Events"), "indicator": "Blue", "datatype": "Int"},
		{"value": ok, "label": _("Successful Logins"), "indicator": "Green", "datatype": "Int"},
		{
			"value": bad,
			"label": _("Failed Logins"),
			"indicator": "Red" if bad else "Grey",
			"datatype": "Int",
		},
		{
			"value": security,
			"label": _("Security Events"),
			"indicator": "Orange",
			"datatype": "Int",
		},
	]
