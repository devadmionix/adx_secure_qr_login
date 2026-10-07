# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Datetime normalisation.

Frappe is inconsistent about the Python type of a `Datetime` field value: a
document loaded through the ORM usually yields a `datetime.datetime`, but the
same field read back from `frappe.db.get_value()`, a row tuple, or a document
built inside a test can arrive as a string. Comparing one of those directly with
`frappe.utils.now()` raises `TypeError` rather than doing the obvious thing.

Both the credential controller and the authentication validator need to compare
timestamps, so the conversion lives here once rather than being copied into each
call site.

This module deliberately has no app imports: it is imported by the DocType
controller and by the security layer, and keeping it dependency-free makes a
circular import impossible.
"""

from datetime import datetime
from typing import Optional

import frappe
from frappe.utils import get_datetime


def as_datetime(value) -> Optional[datetime]:
	"""Return `value` as a `datetime.datetime`, or None when it is empty.

	Accepts a datetime (returned unchanged), a date string in any format
	`frappe.utils.get_datetime` understands, or None/empty. Anything the helper
	cannot parse returns None so a caller compares against "no timestamp"
	instead of crashing on the authentication path.
	"""
	if not value:
		return None
	if isinstance(value, datetime):
		return value
	try:
		return get_datetime(value)
	except Exception:
		return None


def is_future(value) -> bool:
	"""Whether `value` is a timestamp strictly later than now.

	False for empty or unparseable values, so an absent timestamp never
	accidentally reads as "locked until some point in the future".
	"""
	parsed = as_datetime(value)
	current = as_datetime(now())
	if parsed is None or current is None:
		return False
	return parsed > current


def now() -> datetime:
	"""The current time as a `datetime.datetime`.

	`frappe.utils.now()` returns a *string* in this Frappe version while
	`now_datetime()` returns a datetime, and the rest of the app uses both
	interchangeably (a `last_used` written with `now()` reads back as a string).
	Comparisons go through here so the reference value is always a datetime.
	"""
	return frappe.utils.now_datetime()


def seconds_since(value, reference=None) -> Optional[float]:
	"""Seconds elapsed since `value`, or None when it cannot be determined."""
	parsed = as_datetime(value)
	end = as_datetime(reference or now())
	if parsed is None or end is None:
		return None
	return (end - parsed).total_seconds()