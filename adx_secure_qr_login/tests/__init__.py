# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Shared test helpers.

`generate_credential()` and `log_event()` commit, so test data survives the
per-test rollback. Every suite that mints credentials or writes audit rows
must call `cleanup_test_users()` in setUp (kills leftovers from killed runs)
and tearDown, or the dev site fills with `qrtest.*` junk.
"""

import frappe


def cleanup_test_users(emails) -> dict:
	"""Delete test users and everything the suite committed for them.

	Only touches `@test.local` addresses (RFC 6761, never real users).
	Audit rows are removed with SQL because the audit DocType deliberately
	refuses document-layer deletion; this helper is the single sanctioned
	exception, for tests only.
	"""
	from adx_secure_qr_login.security import qr_image

	emails = sorted({e for e in (emails or []) if e and e.endswith("@test.local")})
	removed = {"credentials": 0, "audits": 0, "users": 0}
	if not emails:
		return removed

	for name in frappe.get_all(
		"QR Login Credential", filters={"user": ["in", emails]}, pluck="name"
	):
		try:
			qr_image.delete_qr_files(name)
			frappe.delete_doc(
				"QR Login Credential", name, force=True, ignore_permissions=True
			)
			removed["credentials"] += 1
		except Exception:
			pass

	placeholders = ", ".join(["%s"] * len(emails))
	frappe.db.sql(
		f"DELETE FROM `tabQR Login Audit` WHERE `user` IN ({placeholders})",
		tuple(emails),
	)
	removed["audits"] += frappe.db._cursor.rowcount if frappe.db._cursor else 0
	# Denials are logged with the offender as `actor` and no `user`.
	frappe.db.sql(
		f"DELETE FROM `tabQR Login Audit` WHERE `actor` IN ({placeholders})",
		tuple(emails),
	)
	removed["audits"] += frappe.db._cursor.rowcount if frappe.db._cursor else 0

	for email in emails:
		if frappe.db.exists("User", email):
			try:
				frappe.delete_doc("User", email, force=True, ignore_permissions=True)
				removed["users"] += 1
			except Exception:
				pass

	frappe.db.commit()
	return removed


def cleanup_all_test_users() -> dict:
	"""One-shot dev-site cleanup: every `@test.local` user and its data."""
	emails = frappe.get_all(
		"User", filters={"name": ["like", "%test.local"]}, pluck="name"
	)
	return cleanup_test_users(emails)
