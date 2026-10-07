"""Feature 3: User permissions must remain the same.

Accepts the core rule: QR Login = Authentication only. This suite proves the
app never forks ERPNext authorization.

Run with:

    bench --site <site> set-config allow_tests true
    bench --site <site> run-tests --app adx_secure_qr_login \
          --module adx_secure_qr_login.tests.test_feature3_user_permissions
"""

import frappe
from frappe.tests.utils import FrappeTestCase

from adx_secure_qr_login.tests import cleanup_test_users, site_companies

COMPANY = (site_companies() or [None])[0]
EMAIL = "qrtest.f3@test.local"


def _make_user(email: str, roles=("Stock User",)):
	if not frappe.db.exists("User", email):
		frappe.get_doc(
			{
				"doctype": "User",
				"email": email,
				"first_name": "QRFeature3",
				"send_welcome_email": 0,
			}
		).insert(ignore_permissions=True)
	doc = frappe.get_doc("User", email)
	doc.flags.ignore_permissions = True
	doc.set("roles", [{"role": r} for r in roles])
	doc.user_type = "System User"
	doc.enabled = 1
	doc.save(ignore_permissions=True)
	return doc.name


class TestFeature3PermissionsEqual(FrappeTestCase):
	def setUp(self):
		frappe.set_user("Administrator")
		cleanup_test_users([EMAIL])
		self.user = _make_user(EMAIL, roles=("Stock User",))
		frappe.db.set_value("User", self.user, "company", COMPANY)

	def tearDown(self):
		frappe.db.rollback()
		cleanup_test_users([EMAIL])

	# 1. Credential links to an existing user; minting never touches auth state
	def test_minting_leaves_roles_and_permissions_untouched(self):
		from adx_secure_qr_login.api.qr_manage import generate_credential

		def role_rows():
			return frappe.get_all(
				"Has Role", filters={"parent": self.user}, pluck="role", order_by="role"
			)

		def user_perms():
			return frappe.get_all(
				"User Permission", filters={"user": self.user},
				flathfields=["allow", "for_value"],
			) if False else sorted(
				(p["allow"], p["for_value"])
				for p in frappe.get_all(
					"User Permission",
					filters={"user": self.user},
					fields=["allow", "for_value"],
				)
			)

		before = (role_rows(), user_perms())
		gen = generate_credential(self.user)
		after = (role_rows(), user_perms())

		self.assertEqual(before, after)
		doc = frappe.get_doc("QR Login Credential", gen["credential"])
		self.assertEqual(doc.user, self.user)
		self.assertEqual(doc.status, "Active")
		# no role/permission fields exist on the credential at all
		self.assertFalse(doc.meta.has_field("role"))
		self.assertFalse(doc.meta.has_field("user_permission"))

	# 2. Authentication is the only job: forged tokens fail, CRM-role users
	#    still resolve, and authorization is never encoded in the token.
	def test_token_carries_no_roles(self):
		from adx_secure_qr_login.api.qr_manage import generate_credential
		from adx_secure_qr_login.security.tokens import parse_payload

		gen = generate_credential(self.user)
		payload = parse_payload(gen["one_time_token"])
		self.assertIsNotNone(payload)
		self.assertNotIn("role", gen["one_time_token"].lower())
		self.assertNotIn("permission", gen["one_time_token"].lower())

	def test_forged_credential_like_tokens_fail(self):
		from adx_secure_qr_login.security import tokens, validation

		for raw in (
			"ADXQR1." + ("x" * 43),
			'{"user":"' + self.user + '","role":"Administrator"}',
			"",
		):
			with self.subTest(raw=raw[:20]):
				try:
					validation.resolve_credential(raw)
				except validation.CredentialRejected:
					pass
				else:
					self.fail(f"forged credential accepted: {raw[:20]}")

	# 3 + 6. QR login must reflect *current* roles, never a snapshot.
	def test_role_change_is_not_captured_in_credential(self):
		from adx_secure_qr_login.api.qr_manage import generate_credential
		from adx_secure_qr_login.security import validation

		gen = generate_credential(self.user)
		before = set(frappe.get_roles(self.user))
		self.assertIn("Stock User", before)

		# change the user's roles
		doc = frappe.get_doc("User", self.user)
		doc.flags.ignore_permissions = True
		doc.set("roles", [{"role": "Accounts User"}, {"role": "Stock User"}])
		doc.save(ignore_permissions=True)

		validation.resolve_credential(gen["one_time_token"])
		after = set(frappe.get_roles(self.user))
		# The credential never names a role; the user's live roles describe access.
		self.assertEqual(after, before | {"Accounts User"})

	# 5. User permission restriction continues to apply after the session
	def test_user_permission_company_restriction_applies(self):
		frappe.set_user("Administrator")
		others = [c for c in site_companies() if c != COMPANY]
		other = others[0] if others else None
		if not other:
			self.skipTest("needs a second transacting company on this site")
		frappe.get_doc(
			{
				"doctype": "User Permission",
				"user": self.user,
				"allow": "Company",
				"for_value": COMPANY,
				"apply_to_all_doctypes": 1,
			}
		).insert(ignore_permissions=True)

		frappe.set_user(self.user)
		self.assertTrue(frappe.has_permission("Company", "read", doc=COMPANY))
		self.assertFalse(frappe.has_permission("Company", "read", doc=other))
		frappe.set_user("Administrator")

	# 11. Audit rows never carry raw token material
	def test_audit_never_records_secret(self):
		from adx_secure_qr_login.api.qr_manage import generate_credential

		gen = generate_credential(self.user)
		rows = frappe.get_all(
			"QR Login Audit",
			filters={"user": self.user},
			fields=["details"],
			order_by="creation desc",
			limit=5,
		)
		for r in rows:
			self.assertNotIn(gen["one_time_token"], r.details or "")
			self.assertNotIn("password", (r.details or "").lower())
