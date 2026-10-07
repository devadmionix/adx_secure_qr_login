# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Analysis layer over `QR Login Audit`. Reads only; never writes or copies audit rows.

The category definitions below are the same ones the Security Dashboard uses
(`api/qr_stats.py`): a successful login is a "QR Login Success" row, a failed
login is any `FAILED_LOGIN_EVENTS` row that is not a success, and a security
event is everything that is not a successful login. Keeping them here, and
exposing them to the list view through `quick_filter_definitions`, means the
report, the list shortcuts and the dashboard cannot disagree.

Visibility is never decided here. Rows are fetched through `frappe.get_list`, so
`permissions/audit_conditions.py` (users a manager may see) and the caller's
Company User Permissions apply before a single row reaches the aggregation.
"""

import frappe
from frappe import _
from frappe.utils import get_datetime

from adx_secure_qr_login.security import devices
from adx_secure_qr_login.secure_qr_login.constants import (
	EVENT_LOGIN_SUCCESS,
	EVENTS,
	FAILED_LOGIN_EVENTS,
)

MAX_ROWS = 50000

CATEGORY_ALL = ""
CATEGORY_LOGINS = "All Logins"
CATEGORY_SUCCESS = "Successful Logins"
CATEGORY_FAILED = "Failed Logins"
CATEGORY_SECURITY = "Security Events"
CATEGORIES = (CATEGORY_LOGINS, CATEGORY_SUCCESS, CATEGORY_FAILED, CATEGORY_SECURITY)

LOGIN_EVENTS = tuple(dict.fromkeys((EVENT_LOGIN_SUCCESS, *FAILED_LOGIN_EVENTS)))

GROUP_BY_OPTIONS = ("Result", "User", "Day", "Event", "Company")


def is_successful_login(row) -> bool:
	return row["event"] == EVENT_LOGIN_SUCCESS and bool(row["success"])


def is_failed_login(row) -> bool:
	if row["event"] == EVENT_LOGIN_SUCCESS:
		return not row["success"]
	return row["event"] in FAILED_LOGIN_EVENTS and not row["success"]


def in_category(row, category: str) -> bool:
	if not category:
		return True
	if category == CATEGORY_SUCCESS:
		return is_successful_login(row)
	if category == CATEGORY_FAILED:
		return is_failed_login(row)
	if category == CATEGORY_LOGINS:
		return row["event"] in LOGIN_EVENTS
	if category == CATEGORY_SECURITY:
		return row["event"] != EVENT_LOGIN_SUCCESS
	return True


def result_label(row) -> str:
	return _("Success") if row["success"] else _("Failed")


def day_of(row) -> str:
	return str(get_datetime(row["occurred_on"]).date()) if row.get("occurred_on") else ""


def dimension_value(row, dimension: str) -> str:
	if dimension == "Result":
		return result_label(row)
	if dimension == "User":
		return row.get("user") or _("(unknown)")
	if dimension == "Day":
		return day_of(row)
	if dimension == "Event":
		return row.get("event") or ""
	if dimension == "Company":
		return row.get("company") or _("(none)")
	return ""


def device_label(row) -> str:
	"""Readable device from the stored user agent. The raw string is never shown."""
	if row.get("terminal_label"):
		return row["terminal_label"]
	ua = row.get("user_agent")
	if not ua:
		return ""
	return f"{devices.parse_browser(ua)} on {devices.parse_os(ua)}"


def fetch_rows(filters) -> tuple[list[dict], bool]:
	"""Audit rows for the filters, through the caller's own visibility.

	`frappe.get_list`, never `get_all`: only get_list applies
	permission_query_conditions. Returns (rows, truncated).
	"""
	conditions = {}

	if filters.get("from_date") or filters.get("to_date"):
		start = filters.get("from_date") or "1900-01-01"
		end = filters.get("to_date") or frappe.utils.nowdate()
		conditions["occurred_on"] = (
			"between",
			[
				str(get_datetime(f"{start} 00:00:00")),
				str(get_datetime(f"{end} 23:59:59.999999")),
			],
		)

	for field in ("user", "company", "event", "reason_code"):
		if filters.get(field):
			conditions[field] = filters[field]

	if filters.get("result") == "Success":
		conditions["success"] = 1
	elif filters.get("result") == "Failed":
		conditions["success"] = 0

	rows = frappe.get_list(
		"QR Login Audit",
		filters=conditions,
		fields=[
			"name",
			"occurred_on",
			"user",
			"company",
			"event",
			"success",
			"reason_code",
			"ip_address",
			"user_agent",
			"terminal_label",
			"session_reference",
		],
		order_by="occurred_on desc",
		limit_page_length=MAX_ROWS + 1,
	)

	truncated = len(rows) > MAX_ROWS
	rows = rows[:MAX_ROWS]
	category = filters.get("category")
	if category:
		rows = [r for r in rows if in_category(r, category)]
	return rows, truncated


def group(rows: list[dict], group_by: str, pivot_by: str | None = None):
	"""Count rows by `group_by`, optionally spread across `pivot_by` columns.

	Returns (groups, pivot_values) where groups is a list of
	{"key", "total", "success", "failed", "cells": {pivot_value: count}}.
	"""
	buckets: dict[str, dict] = {}
	pivot_values: dict[str, int] = {}

	for r in rows:
		key = dimension_value(r, group_by)
		b = buckets.setdefault(
			key, {"key": key, "total": 0, "success": 0, "failed": 0, "cells": {}}
		)
		b["total"] += 1
		if r["success"]:
			b["success"] += 1
		else:
			b["failed"] += 1
		if pivot_by:
			pv = dimension_value(r, pivot_by)
			b["cells"][pv] = b["cells"].get(pv, 0) + 1
			pivot_values[pv] = pivot_values.get(pv, 0) + 1

	groups = list(buckets.values())
	if group_by == "Day":
		groups.sort(key=lambda g: g["key"])
	else:
		groups.sort(key=lambda g: (-g["total"], g["key"]))

	ordered_pivots = sorted(pivot_values) if pivot_by == "Day" else sorted(
		pivot_values, key=lambda v: (-pivot_values[v], v)
	)
	return groups, ordered_pivots


def chart_for(rows: list[dict], kind: str) -> dict | None:
	"""Chart datasets, built from the already-scoped rows only."""
	if kind == "Logins by Day":
		by_day: dict[str, list[int]] = {}
		for r in rows:
			ok, bad = is_successful_login(r), is_failed_login(r)
			if not (ok or bad):
				continue
			cell = by_day.setdefault(day_of(r), [0, 0])
			cell[0 if ok else 1] += 1
		if not by_day:
			return None
		days = sorted(by_day)
		return {
			"type": "bar",
			"data": {
				"labels": days,
				"datasets": [
					{"name": _("Successful"), "values": [by_day[d][0] for d in days]},
					{"name": _("Failed"), "values": [by_day[d][1] for d in days]},
				],
			},
			"colors": ["#2f9e44", "#e03131"],
		}

	if kind == "Events by Type":
		counts: dict[str, int] = {}
		for r in rows:
			counts[r["event"]] = counts.get(r["event"], 0) + 1
		if not counts:
			return None
		ordered = sorted(counts, key=lambda e: -counts[e])
		return {
			"type": "bar",
			"data": {
				"labels": ordered,
				"datasets": [{"name": _("Events"), "values": [counts[e] for e in ordered]}],
			},
		}

	# Default: successful vs failed logins.
	ok = sum(1 for r in rows if is_successful_login(r))
	bad = sum(1 for r in rows if is_failed_login(r))
	if not (ok or bad):
		return None
	return {
		"type": "donut",
		"data": {
			"labels": [_("Successful Logins"), _("Failed Logins")],
			"datasets": [{"values": [ok, bad]}],
		},
		"colors": ["#2f9e44", "#e03131"],
	}


@frappe.whitelist()
def quick_filter_definitions() -> dict:
	"""List-view filters for each quick filter, derived from the same constants."""
	return {
		CATEGORY_SUCCESS: [
			["QR Login Audit", "event", "=", EVENT_LOGIN_SUCCESS],
			["QR Login Audit", "success", "=", 1],
		],
		CATEGORY_FAILED: [
			["QR Login Audit", "event", "in", list(FAILED_LOGIN_EVENTS)],
			["QR Login Audit", "success", "=", 0],
		],
		CATEGORY_LOGINS: [["QR Login Audit", "event", "in", list(LOGIN_EVENTS)]],
		CATEGORY_SECURITY: [["QR Login Audit", "event", "!=", EVENT_LOGIN_SUCCESS]],
	}
