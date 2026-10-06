# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Script Report: Weekly Security Report (graphical, filterable).

Reads the stored `Weekly Security Report` records -- the same rows the
Monday scheduler and the manual button create -- so the report, the emailed
summary and the desk list can never disagree.

Returns (columns, data, message, chart, report_summary):
* one row per stored week in the filter range,
* a bar chart of successful vs failed logins per week,
* summary cards for the latest week in range.
"""

import frappe

COLUMNS = [
	{"label": "Period", "fieldname": "period", "fieldtype": "Data", "width": 200},
	{
		"label": "Successful Logins",
		"fieldname": "successful_logins",
		"fieldtype": "Int",
		"width": 140,
	},
	{
		"label": "Failed Attempts",
		"fieldname": "failed_attempts",
		"fieldtype": "Int",
		"width": 130,
	},
	{
		"label": "Active Credentials",
		"fieldname": "active_credentials",
		"fieldtype": "Int",
		"width": 150,
	},
	{
		"label": "Expired Credentials",
		"fieldname": "expired_credentials",
		"fieldtype": "Int",
		"width": 160,
	},
	{
		"label": "Revoked Credentials",
		"fieldname": "revoked_credentials",
		"fieldtype": "Int",
		"width": 160,
	},
]


def execute(filters=None):
	from adx_secure_qr_login.security.weekly_report import assert_can_access_report

	assert_can_access_report("weekly_security_report")
	filters = filters or {}

	conditions = []
	args = []
	if filters.get("from_date"):
		conditions.append("period_start >= %s")
		args.append(str(filters["from_date"]))
	if filters.get("to_date"):
		conditions.append("period_start <= %s")
		args.append(str(filters["to_date"]))

	where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
	rows = frappe.db.sql(
		f"""
		SELECT period_start, period_end,
			successful_logins, failed_attempts,
			active_credentials, expired_credentials, revoked_credentials
		FROM `tabWeekly Security Report`
		{where}
		ORDER BY period_start
		""",
		tuple(args),
		as_dict=True,
	)

	if not rows:
		return (
			COLUMNS,
			[],
			"No weekly reports in this period yet. Reports generate every Monday, or use Generate Weekly Security Report in QR Security Settings.",
			None,
			None,
		)

	labels, data, successful, failed = [], [], [], []
	for row in rows:
		label = (
			f"{frappe.utils.formatdate(row.period_start, 'dd MMM')} - "
			f"{frappe.utils.formatdate(row.period_end, 'dd MMM yyyy')}"
		)
		labels.append(label)
		data.append(
			{
				"period": label,
				"successful_logins": row.successful_logins,
				"failed_attempts": row.failed_attempts,
				"active_credentials": row.active_credentials,
				"expired_credentials": row.expired_credentials,
				"revoked_credentials": row.revoked_credentials,
			}
		)
		successful.append(row.successful_logins or 0)
		failed.append(row.failed_attempts or 0)

	chart = {
		"data": {
			"labels": labels,
			"datasets": [
				{"name": "Successful Logins", "values": successful},
				{"name": "Failed Attempts", "values": failed},
			],
		},
		"type": "bar",
	}

	latest = rows[-1]
	latest_label = labels[-1]
	report_summary = [
		{
			"value": latest.successful_logins or 0,
			"indicator": "Green",
			"label": f"Successful Logins ({latest_label})",
		},
		{
			"value": latest.failed_attempts or 0,
			"indicator": "Red" if (latest.failed_attempts or 0) else "Grey",
			"label": f"Failed Attempts ({latest_label})",
		},
		{
			"value": latest.active_credentials or 0,
			"indicator": "Blue",
			"label": "Active Credentials",
		},
		{
			"value": latest.expired_credentials or 0,
			"indicator": "Orange",
			"label": "Expired During Week",
		},
		{
			"value": latest.revoked_credentials or 0,
			"indicator": "Orange",
			"label": "Revoked During Week",
		},
	]

	return COLUMNS, data, None, chart, report_summary
