"""Multi-company isolation and direct-API authorization.

These are the highest-priority security requirements: company isolation must be
enforced **server-side**, and it must hold for direct API calls, not only for
the desk UI. A UI that merely hides a row proves nothing -- the server has to
refuse.

Everything here goes through Frappe's real permission engine
(`permission_query_conditions` / `has_permission`) by calling the whitelisted
methods as a non-Administrator user. Frappe's `Administrator` short-circuits
both, so every case asserts on an ordinary QR Manager.
"""

import frappe
from frappe.tests.utils import FrappeTestCase

from adx_secure_qr_login.secure_qr_login.constants import ROLE_ADMIN, ROLE_MANAGER
from adx_secure_qr_login.tests import cleanup_test_users, require_companies

COMPANY_A, COMPANY_B = (require_companies(2) + [None, None])[:2]

MANAGER_A = "qrtest.mc.mgr_a@test.local"
MANAGER_B = "qrtest.mc.mgr_b@test.local"
USER_A = "qrtest.mc.user_a@test.local"
USER_B = "qrtest.mc.user_b@test.local"


def _make_user(email, company, roles=("Stock User",)):
	if not frappe.db.exists("User", email):
		frappe.get_doc(
			{
				"doctype": "User",
				"email": email,
				"first_name": "QRMulti",
				"send_welcome_email": 0,
				"company": company,
			}
		).insert(ignore_permissions=True)

	doc = frappe.get_doc("User", email)
	doc.flags.ignore_permissions = True
	doc.set("roles", [{"role": r} for r in roles])
	doc.user_type = "System User"
	doc.enabled = 1
	doc.company = company
	doc.save(ignore_permissions=True)

	# The Company User Permission is what ERPNext itself uses to scope a user to
	# one company. The QR layer must respect it rather than reimplement it.
	existing = frappe.db.exists(
		"User Permission", {"user": email, "allow": "Company", "for_value": company}
	)
	if not existing:
		frappe.get_doc(
			{
				"doctype": "User Permission",
				"user": email,
				"allow": "Company",
				"for_value": company,
				"apply_to_all_doctypes": 1,
			}
		).insert(ignore_permissions=True)

	return doc.name


class TestMultiCompanyIsolation(FrappeTestCase):
	USERS = (MANAGER_A, MANAGER_B, USER_A, USER_B)

	def setUp(self):
		frappe.set_user("Administrator")
		cleanup_test_users(self.USERS)
		self.manager_a = _make_user(MANAGER_A, COMPANY_A, (ROLE_MANAGER, "Stock User"))
		self.manager_b = _make_user(MANAGER_B, COMPANY_B, (ROLE_MANAGER, "Stock User"))
		self.user_a = _make_user(USER_A, COMPANY_A)
		self.user_b = _make_user(USER_B, COMPANY_B)
		frappe.db.commit()

		# One credential per company.
		self.cred_a = self._mint(self.user_a)
		self.cred_b = self._mint(self.user_b)

	def tearDown(self):
		frappe.set_user("Administrator")
		frappe.db.rollback()
		cleanup_test_users(self.USERS)

	def _mint(self, user):
		from adx_secure_qr_login.api.qr_manage import generate_credential

		frappe.set_user("Administrator")
		return generate_credential(user)["credential"]

	# -- credentials ---------------------------------------------------

	def test_manager_cannot_see_other_company_credentials(self):
		frappe.set_user(self.manager_a)
		rows = frappe.get_list(
			"QR Login Credential", filters={"user": self.user_b}, pluck="name"
		)
		self.assertEqual(rows, [], "Company A manager can list a Company B credential")

	def test_manager_cannot_read_other_company_credential_directly(self):
		"""A direct docname reference must fail, not just an empty list.

		`frappe.get_doc` is the low-level loader and deliberately skips
		permission checks, so the gate under test is `frappe.has_permission` --
		the function `frappe.client.get_value` and the desk form both go through.
		"""
		frappe.set_user(self.manager_a)
		self.assertFalse(
			frappe.has_permission("QR Login Credential", "read", self.cred_b),
			"Company A manager has read permission on a Company B credential",
		)
		self.assertTrue(
			frappe.has_permission("QR Login Credential", "read", self.cred_a),
			"Company A manager lost read on its own credential",
		)

	def test_manager_sees_own_company_credential(self):
		frappe.set_user(self.manager_a)
		rows = frappe.get_list(
			"QR Login Credential", filters={"user": self.user_a}, pluck="name"
		)
		self.assertIn(self.cred_a, rows)

	def test_manager_cannot_revoke_other_company_credential(self):
		from adx_secure_qr_login.api import qr_manage

		frappe.set_user(self.manager_a)
		with self.assertRaises(frappe.PermissionError):
			qr_manage.revoke_credential(self.cred_b, reason="cross-company")

	def test_manager_cannot_regenerate_other_company_credential(self):
		from adx_secure_qr_login.api import qr_manage

		frappe.set_user(self.manager_a)
		with self.assertRaises(frappe.PermissionError):
			qr_manage.regenerate_credential(self.cred_b)

	def test_manager_cannot_mint_credential_for_other_company_user(self):
		from adx_secure_qr_login.api import qr_manage

		frappe.set_user(self.manager_a)
		with self.assertRaises(frappe.PermissionError):
			qr_manage.generate_credential(self.user_b)

	def test_manager_cannot_download_other_company_qr(self):
		"""The PNG is a faithful rendering of the bearer token, so it matters."""
		from adx_secure_qr_login.api import qr_manage

		frappe.set_user(self.manager_a)
		with self.assertRaises(frappe.PermissionError):
			qr_manage.get_qr_data_uri(self.cred_b)

	# -- audit trail ----------------------------------------------------

	def test_manager_cannot_read_other_company_audit_rows(self):
		from adx_secure_qr_login.secure_qr_login.doctype.qr_login_audit.qr_login_audit import (
			log_event,
		)

		frappe.set_user("Administrator")
		log_event(
			"QR Login Success",
			user=self.user_b,
			success=True,
			company=COMPANY_B,
			commit=True,
		)

		frappe.set_user(self.manager_a)
		rows = frappe.get_list(
			"QR Login Audit", filters={"user": self.user_b}, pluck="name"
		)
		self.assertEqual(rows, [], "Company A manager can read Company B audit rows")

	def test_manager_sees_own_company_audit_rows(self):
		from adx_secure_qr_login.secure_qr_login.doctype.qr_login_audit.qr_login_audit import (
			log_event,
		)

		frappe.set_user("Administrator")
		log_event(
			"QR Login Success",
			user=self.user_a,
			success=True,
			company=COMPANY_A,
			commit=True,
		)

		frappe.set_user(self.manager_a)
		rows = frappe.get_list(
			"QR Login Audit", filters={"user": self.user_a}, pluck="name"
		)
		self.assertTrue(rows)

	# -- devices --------------------------------------------------------

	def test_manager_cannot_see_other_company_devices(self):
		frappe.set_user(self.manager_a)
		rows = frappe.get_list(
			"QR Login Device", filters={"user": self.user_b}, pluck="name"
		)
		self.assertEqual(rows, [], "Company A manager can list Company B devices")

	def test_manager_cannot_revoke_other_company_device(self):
		frappe.set_user("Administrator")
		doc = frappe.get_doc(
			{
				"doctype": "QR Login Device",
				"device_id": "mc-device-b",
				"device_name": "Company B kiosk",
				"user": self.user_b,
				"company": COMPANY_B,
			}
		)
		doc.insert(ignore_permissions=True)
		frappe.db.commit()

		from adx_secure_qr_login.api import qr_device

		frappe.set_user(self.manager_a)
		with self.assertRaises(frappe.PermissionError):
			qr_device.revoke_device(doc.name)

	def test_user_cannot_see_other_users_devices(self):
		frappe.set_user("Administrator")
		doc = frappe.get_doc(
			{
				"doctype": "QR Login Device",
				"device_id": "mc-device-a",
				"device_name": "Company A laptop",
				"user": self.user_a,
				"company": COMPANY_A,
			}
		)
		doc.insert(ignore_permissions=True)
		frappe.db.commit()

		frappe.set_user(self.user_b)
		rows = frappe.get_list(
			"QR Login Device", filters={"user": self.user_a}, pluck="name"
		)
		self.assertEqual(rows, [])

	# -- dashboard / stats ----------------------------------------------

	def test_dashboard_is_company_isolated(self):
		"""A manager's dashboard must aggregate only its own company.

		Expressed as membership rather than counts: the site may legitimately hold
		other credentials from other users, so asserting an exact total would be
		brittle. What matters is that neither manager's figures include the other
		company's credential.
		"""
		frappe.set_user(self.manager_a)
		seen_by_a = frappe.get_list(
			"QR Login Credential", pluck="name", limit_page_length=0
		)
		frappe.set_user(self.manager_b)
		seen_by_b = frappe.get_list(
			"QR Login Credential", pluck="name", limit_page_length=0
		)

		self.assertIn(self.cred_a, seen_by_a)
		self.assertNotIn(self.cred_b, seen_by_a)
		self.assertIn(self.cred_b, seen_by_b)
		self.assertNotIn(self.cred_a, seen_by_b)

		from adx_secure_qr_login.api.qr_stats import credential_counts

		frappe.set_user(self.manager_a)
		mine = credential_counts()["total"]
		frappe.set_user("Administrator")
		site_total = credential_counts()["total"]

		self.assertLess(
			mine, site_total,
			"Company A manager sees every credential on the site -- company "
			"isolation is not reaching the stats endpoint",
		)

	def test_qr_admin_dashboard_is_unrestricted(self):
		"""A cross-company administrator must not be broken by the scoping."""
		from adx_secure_qr_login.api.qr_stats import credential_counts
		from adx_secure_qr_login.security import rbac

		frappe.set_user("Administrator")
		admin_total = credential_counts()["total"]

		admin = _make_user(
			"qrtest.mc.admin@test.local", COMPANY_A, (ROLE_ADMIN, "Stock User")
		)
		try:
			frappe.set_user(admin)
			self.assertTrue(rbac.is_qr_admin(admin))
			self.assertEqual(
				credential_counts()["total"],
				admin_total,
				"QR Admin lost cross-company visibility on the dashboard",
			)
		finally:
			cleanup_test_users(["qrtest.mc.admin@test.local"])

	# -- user list isolation --------------------------------------------

	def test_user_list_is_company_isolated(self):
		frappe.set_user(self.manager_a)
		rows = frappe.get_list("User", pluck="name", limit_page_length=0)
		self.assertIn(self.user_a, rows)
		self.assertNotIn(
			self.user_b, rows, "Company A manager can see a Company B user"
		)


class TestDirectApiAuthorization(FrappeTestCase):
	"""PHASE 20: every sensitive endpoint must refuse an unprivileged caller.

	Called as a plain System User -- no QR role at all -- so a UI-only
	restriction would not satisfy these.
	"""

	def setUp(self):
		frappe.set_user("Administrator")
		cleanup_test_users([USER_A])
		self.plain = _make_user(USER_A, COMPANY_A)
		self.cred = self._mint(self.plain)
		frappe.db.commit()

	def tearDown(self):
		frappe.set_user("Administrator")
		frappe.db.rollback()
		cleanup_test_users([USER_A])

	def _mint(self, user):
		from adx_secure_qr_login.api.qr_manage import generate_credential

		frappe.set_user("Administrator")
		return generate_credential(user)["credential"]

	def test_plain_user_cannot_manage_another_users_credential(self):
		"""No QR role must mean no authority over someone else's credential.

		Note this deliberately targets *another* user. Reading one's own
		credential is intended behaviour (spec 6.2 lets a user download their own
		QR), so probing that would assert the opposite of the requirement.
		"""
		from adx_secure_qr_login.api import qr_manage

		other = _make_user("qrtest.mc.victim@test.local", COMPANY_B)
		self.addCleanup(cleanup_test_users, ["qrtest.mc.victim@test.local"])
		victim_cred = self._mint(other)

		frappe.set_user(self.plain)
		cases = {
			"generate": lambda: qr_manage.generate_credential(other),
			"regenerate": lambda: qr_manage.regenerate_credential(victim_cred),
			"revoke": lambda: qr_manage.revoke_credential(victim_cred, "x"),
			"get": lambda: qr_manage.get_credential(victim_cred),
			"list": lambda: qr_manage.list_user_credentials(other),
			"download": lambda: qr_manage.get_qr_data_uri(victim_cred),
		}
		for label, call in cases.items():
			with self.subTest(endpoint=label):
				with self.assertRaises(frappe.PermissionError):
					call()

	def test_plain_user_refused_by_privileged_endpoints(self):
		"""Reporting and device administration need a QR role outright."""
		from adx_secure_qr_login.api import qr_device, qr_manage, qr_stats

		frappe.set_user(self.plain)
		cases = {
			"dashboard": lambda: qr_stats.dashboard_data(),
			"weekly_report": lambda: qr_stats.weekly_report_data(),
			"terminate": lambda: qr_manage.terminate_user_sessions(self.plain),
			"revoke_device": lambda: qr_device.revoke_device("nope"),
			"trust_device": lambda: qr_device.trust_device("nope"),
		}
		for label, call in cases.items():
			with self.subTest(endpoint=label):
				with self.assertRaises(frappe.PermissionError):
					call()

	def test_plain_user_may_still_read_their_own_credential(self):
		"""Self-service must survive the tightening (Phase 30).

		Guards against "fixing" isolation by locking every user out of their own
		QR, which would break the shipped self-service workflow.
		"""
		from adx_secure_qr_login.api import qr_manage

		frappe.set_user(self.plain)
		payload = qr_manage.get_credential(self.cred)
		self.assertEqual(payload["user"], self.plain)
		self.assertTrue(qr_manage.list_user_credentials(self.plain))

	def test_admin_role_is_still_required_for_settings(self):
		"""A QR Manager must not be able to weaken policy."""
		from adx_secure_qr_login.security import rbac

		manager = _make_user(
			"qrtest.mc.settings_mgr@test.local", COMPANY_A, (ROLE_MANAGER, "Stock User")
		)
		try:
			frappe.set_user(manager)
			with self.assertRaises(frappe.PermissionError):
				rbac.assert_is_qr_admin("change_settings")
		finally:
			cleanup_test_users(["qrtest.mc.settings_mgr@test.local"])

	def test_qr_admin_privilege_is_not_reachable_through_a_manager(self):
		"""A manager must not be able to act on a privileged account.

		Only privileged targets are probed: managing an ordinary colleague inside
		the manager's own company is legitimate and must keep working.
		"""
		from adx_secure_qr_login.security import rbac

		privileged = _make_user(
			"qrtest.mc.peer_admin@test.local", COMPANY_A, (ROLE_ADMIN, "Stock User")
		)
		manager = _make_user(
			"qrtest.mc.esc_mgr@test.local", COMPANY_A, (ROLE_MANAGER, "Stock User")
		)
		try:
			frappe.set_user(manager)
			for target in ("Administrator", privileged):
				with self.subTest(target=target):
					with self.assertRaises(frappe.PermissionError):
						rbac.assert_can_manage_target("test", target)

			# Same-company ordinary user stays manageable.
			rbac.assert_can_manage_target("test", self.plain)
		finally:
			cleanup_test_users(
				["qrtest.mc.esc_mgr@test.local", "qrtest.mc.peer_admin@test.local"]
			)


class TestUserPermissionPreservation(FrappeTestCase):
	"""PHASE 5: ERPNext stays the source of truth; QR caches no authorization."""

	def setUp(self):
		frappe.set_user("Administrator")
		cleanup_test_users([USER_A])
		self.user = _make_user(USER_A, COMPANY_A)
		from adx_secure_qr_login.api.qr_manage import generate_credential

		self.gen = generate_credential(self.user)

	def tearDown(self):
		frappe.set_user("Administrator")
		frappe.db.rollback()
		cleanup_test_users([USER_A])

	def test_credential_carries_no_authorization_state(self):
		doc = frappe.get_doc("QR Login Credential", self.gen["credential"])
		for forbidden in ("role", "roles", "user_permission", "permissions", "company"):
			self.assertFalse(
				doc.meta.has_field(forbidden),
				f"QR Login Credential must not carry a '{forbidden}' field",
			)

	def test_role_change_takes_effect_on_the_next_login(self):
		from adx_secure_qr_login.security import validation

		before = set(frappe.get_roles(self.user))
		self.assertIn("Stock User", before)

		doc = frappe.get_doc("User", self.user)
		doc.flags.ignore_permissions = True
		doc.set("roles", [{"role": "Accounts User"}, {"role": "Stock User"}])
		doc.save(ignore_permissions=True)

		# The already-issued credential still authenticates, and the user's live
		# roles now describe their access.
		validation.resolve_credential(self.gen["one_time_token"])
		self.assertEqual(
			set(frappe.get_roles(self.user)), before | {"Accounts User"}
		)

	def test_company_change_takes_effect_on_the_next_login(self):
		from adx_secure_qr_login.security import validation

		validation.resolve_credential(self.gen["one_time_token"])

		frappe.db.set_value("User", self.user, "company", COMPANY_B)
		self.assertEqual(validation.get_user_company(self.user), COMPANY_B)

		# Same credential, no re-mint: the new company governs the next login.
		self.assertEqual(
			validation.resolve_credential(self.gen["one_time_token"]),
			self.gen["credential"],
		)