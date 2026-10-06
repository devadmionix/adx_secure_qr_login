"""Backfill the security settings added in v0.0.2.

The new Checks in QR Security Settings carry a `default` in the DocType, but
that only fires on **insert**. QR Security Settings is a *Single*, so its single
row is created once by the bootstrap patch and then reused for the life of the
site -- on an upgraded install the new fields never get their defaults and read
as 0/None instead.

That is not cosmetic: `audit_logging_enabled` reading 0 would silently stop
every audit write, and `require_https` reading 0 would leave QR login accepting a
bearer credential over cleartext HTTP.

Fails closed on intent: the values written here are the DocType defaults, i.e.
the secure choice, so a site that upgrades gets stricter behaviour, not looser.
"""

import frappe

SETTINGS = "QR Security Settings"

# field -> value. Only written where the field is currently unset (0/None/""),
# so an explicit choice made after the upgrade is never clobbered.
BACKFILL = (
	("require_https", 1),
	("manager_company_scope_enabled", 1),
	("allow_self_download", 1),
	("audit_logging_enabled", 1),
	("weekly_report_timezone", "Asia/Kolkata"),
)


def execute():
	if not frappe.db.exists("DocType", SETTINGS):
		return

	fields = [field for field, _ in BACKFILL]

	# Singles are read through tabSingles; `frappe.db.get_value` raises on them.
	try:
		current = frappe.db.get_singles_dict(SETTINGS, cast=True)
	except Exception:
		current = {}

	if not current:
		# No settings row written yet. get_settings() will create one on first
		# read, and the DocType defaults apply to that insert.
		return

	changed = {
		field: value
		for field, value in BACKFILL
		if current.get(field) in (None, "", 0)
	}
	if not changed:
		return

	frappe.db.set_single_value(
		SETTINGS,
		changed,
		modified=frappe.utils.now(),
		modified_by=frappe.session.user,
	)
	frappe.db.commit()