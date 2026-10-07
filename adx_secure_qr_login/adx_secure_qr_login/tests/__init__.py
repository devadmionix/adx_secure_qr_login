# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Shared test helpers.

`generate_credential()` and `log_event()` commit, so test data survives the
per-test rollback. Every suite that mints credentials or writes audit rows
must call `cleanup_test_users()` in setUp (kills leftovers from killed runs)
and tearDown, or the dev site fills with `qrtest.*` junk.
"""

import frappe


def site_companies() -> list[str]:
	"""Transacting companies that actually exist on the site under test.

	The multi-company suites used to hardcode `Admionix` / `Admionix-2`, which
	only ever existed on one developer's database. On any other site the Link
	validator raised `Could not find Company` and the whole module errored before
	a single assertion ran -- a test-portability bug, not an application defect.

	Group companies are excluded: they cannot be assigned to a user or used as a
	QR login company, so they are never valid fixtures here.
	"""
	return frappe.get_all(
		"Company", filters={"is_group": 0}, pluck="name", order_by="creation asc"
	)


def require_companies(count: int = 1) -> list[str]:
	"""Like `site_companies()` but skips the test when the site is too small.

	Callers `self.skipTest(...)` so an under-provisioned site reports an honest
	skip rather than a false pass.
	"""
	companies = site_companies()
	if len(companies) < count:
		from frappe.tests.utils import skip_test

		skip_test(
			f"needs {count} transacting compan"
			f"{'y' if count == 1 else 'ies'} on this site, found {len(companies)}"
		)
	return companies


def cleanup_test_users(emails) -> dict:
	"""Delete test users and everything the suite committed for them.

	Only touches `@test.local` addresses (RFC 6761, never real users).

	Rows are removed with SQL rather than `delete_doc` because several of these
	DocTypes refuse document-layer deletion by design, and because a killed test
	run can leave a user already deleted while its child rows survive -- which
	then breaks Link validation for the *next* run and cascades into unrelated
	errors. SQL cleanup is unconditional and therefore self-healing.
	"""
	from adx_secure_qr_login.security import qr_image

	emails = sorted({e for e in (emails or []) if e and e.endswith("@test.local")})
	removed = {"credentials": 0, "audits": 0, "users": 0, "devices": 0}
	if not emails:
		return removed

	placeholders = ", ".join(["%s"] * len(emails))

	# Stored QR images are files, not rows: they have to go through the helper or
	# they leak in `private/files` forever.
	for name in frappe.get_all(
		"QR Login Credential", filters={"user": ["in", emails]}, pluck="name"
	):
		try:
			qr_image.delete_qr_files(name)
		except Exception:
			pass

	# Children first, parents last, all unconditional.
	for table, column in (
		("QR Login Device", "user"),
		("QR Login Audit", "user"),
		("QR Login Audit", "actor"),
		("QR Login Audit", "credential"),
	):
		try:
			if column == "credential":
				frappe.db.sql(
					f"DELETE FROM `tab{table}` WHERE `{column}` IN "
					f"(SELECT name FROM `tabQR Login Credential` WHERE `user` IN ({placeholders}))",
					tuple(emails),
				)
			else:
				frappe.db.sql(
					f"DELETE FROM `tab{table}` WHERE `{column}` IN ({placeholders})",
					tuple(emails),
				)
			if frappe.db._cursor:
				removed["audits" if table == "QR Login Audit" else "devices"] += (
					frappe.db._cursor.rowcount
				)
		except Exception:
			pass

	try:
		frappe.db.sql(
			f"DELETE FROM `tabQR Login Credential` WHERE `user` IN ({placeholders})",
			tuple(emails),
		)
		if frappe.db._cursor:
			removed["credentials"] += frappe.db._cursor.rowcount
	except Exception:
		pass

	# Child tables of User (roles, user permissions, ...) must go before the user.
	for table, column in (
		("User Permission", "user"),
		("Has Role", "parent"),
		("User Email", "parent"),
		("User", "name"),
	):
		try:
			frappe.db.sql(
				f"DELETE FROM `tab{table}` WHERE `{column}` IN ({placeholders})",
				tuple(emails),
			)
			if table == "User" and frappe.db._cursor:
				removed["users"] += frappe.db._cursor.rowcount
		except Exception:
			pass

	frappe.db.commit()
	return removed
