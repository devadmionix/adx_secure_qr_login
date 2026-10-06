"""Automatic QR credential creation + welcome email (feature spec tests).

Covers the auto-issue hook's own guarantees; the login/expiry/revocation/
permission-matrix legs of the spec are covered by test_qr_login and
test_user_company.

Run with:
    bench --site <site> run-tests --app adx_secure_qr_login \
          --module adx_secure_qr_login.tests.test_auto_issue_flow
"""

import frappe
from frappe.tests.utils import FrappeTestCase

from adx_secure_qr_login.api import qr_manage
from adx_secure_qr_login.secure_qr_login.constants import CREDENTIAL_STATUS_ACTIVE
from adx_secure_qr_login.tests import cleanup_test_users

COMPANY = "Admionix"


def _create_user(email, **overrides):
	fields = {
		"doctype": "User",
		"email": email,
		"first_name": "QRAuto",
		"last_name": "Flow",
		"send_welcome_email": 0,
		"company": COMPANY,
		"roles": [{"role": "Stock User"}],
	}
	fields.update(overrides)
	frappe.flags.in_test = False
	try:
		doc = frappe.get_doc(fields)
		doc.insert(ignore_permissions=True)
	finally:
		frappe.flags.in_test = True
	return doc


def _refire_hook(doc):
	"""Simulate the after_insert hook firing a second time (real request mode)."""
	frappe.flags.in_test = False
	try:
		return qr_manage.issue_credential_for_new_user(doc)
	finally:
		frappe.flags.in_test = True


class TestAutoIssueFlow(FrappeTestCase):
	def setUp(self):
		frappe.set_user("Administrator")
		frappe.db.set_single_value(
			"QR Security Settings", "auto_issue_credential_on_user_create", 1
		)

	def tearDown(self):
		frappe.db.rollback()
		cleanup_test_users(
			[
				"qrtest.flow1@test.local",
				"qrtest.flow2@test.local",
				"qrtest.flow3@test.local",
				"qrtest.flow4@test.local",
				"qrtest.flow5@test.local",
			]
		)

	def _mails(self, fn, *args, **kwargs):
		sent = []
		original = frappe.sendmail
		frappe.sendmail = lambda **kw: sent.append(kw)
		try:
			result = fn(*args, **kwargs)
		finally:
			frappe.sendmail = original
		return result, sent

	def test_new_user_gets_active_credential_and_full_mail(self):
		"""Spec Test 1: user -> linked Active credential + structured mail."""
		email = "qrtest.flow1@test.local"
		cleanup_test_users([email])

		doc, sent = self._mails(_create_user, email, send_welcome_email=1)

		creds = frappe.get_all(
			"QR Login Credential", filters={"user": email}, fields=["name", "status"]
		)
		self.assertEqual(len(creds), 1)
		self.assertEqual(creds[0].status, CREDENTIAL_STATUS_ACTIVE)

		# Ownership marker.
		self.assertIn(
			"Auto-issued",
			frappe.db.get_value("QR Login Credential", creds[0].name, "device_label") or "",
		)

		# Stored printable QR exists (re-printable without the token).
		from adx_secure_qr_login.security import qr_image

		self.assertTrue(qr_image.qr_file_exists(creds[0].name))

		# Exactly one mail (core's duplicate suppressed), spec content present.
		core_mails = [m for m in sent]
		self.assertEqual(len(core_mails), 1)
		mail = core_mails[0]
		self.assertEqual(mail["recipients"], [email])
		self.assertIn("Secure QR Login", mail["subject"])
		body = mail["message"]
		for needle in (
			"Your Login QR Code",
			"Download My QR Code",
			"Login with QR",
			"Credential Status: <strong>Active</strong>",
			"Expiration Date:",
			"Your Secure QR Login credential has been created successfully",
			"securely log in to ERPNext",
			"keep your QR code secure",
			"contact your administrator",
			"Regards,",
			"download_qr_image",
			"/login",
		):
			self.assertIn(needle, body)
		# QR shown inline via a Content-ID reference.
		self.assertIn(f'embed="{email.split("@")[0]}-qr.png"', body)
		self.assertTrue(mail.get("inline_images"))
		# No password material anywhere: only a setup *link* (key, not a secret).
		self.assertIn("update-password?key=", body)
		for banned in ("api_secret", "user_password", "new_password=", "password_hash"):
			self.assertNotIn(banned, body.lower())

	def test_duplicate_prevention_second_trigger_mints_nothing(self):
		"""Spec Test 3: re-fired hook neither mints nor re-mails."""
		email = "qrtest.flow2@test.local"
		cleanup_test_users([email])

		doc, sent = self._mails(_create_user, email)
		first = frappe.get_all(
			"QR Login Credential", filters={"user": email}, pluck="name"
		)
		self.assertEqual(len(first), 1)
		mail_count = len(sent)

		again, sent2 = self._mails(_refire_hook, doc)
		second = frappe.get_all(
			"QR Login Credential", filters={"user": email}, pluck="name"
		)
		self.assertEqual(second, first)
		self.assertTrue(again.get("already_existed"))
		self.assertEqual(len(sent2), 0)
		self.assertEqual(mail_count, len(sent))

	def test_mint_failure_keeps_user_and_logs(self):
		"""Spec failure case 1: QR failure must not break User creation."""
		email = "qrtest.flow3@test.local"
		cleanup_test_users([email])

		original_mint = qr_manage._mint

		def _boom(*args, **kwargs):
			raise RuntimeError("simulated mint failure")

		qr_manage._mint = _boom
		frappe.flags.in_test = False
		try:
			doc = frappe.get_doc(
				{
					"doctype": "User",
					"email": email,
					"first_name": "QRAuto",
					"send_welcome_email": 0,
					"company": COMPANY,
					"roles": [{"role": "Stock User"}],
				}
			)
			doc.insert(ignore_permissions=True)
		finally:
			qr_manage._mint = original_mint
			frappe.flags.in_test = True

		# User creation succeeded...
		self.assertTrue(frappe.db.exists("User", email))
		# ...with no credential and no mail claiming one is ready...
		self.assertEqual(
			frappe.db.count("QR Login Credential", {"user": email}), 0
		)
		# ...and an administrator-visible Error Log entry.
		self.assertGreaterEqual(
			frappe.db.count("Error Log", {"method": "QR auto-issue failed"}), 1
		)

	def test_email_failure_keeps_credential(self):
		"""Spec failure case 2: mail failure keeps the credential for resend."""
		email = "qrtest.flow4@test.local"
		cleanup_test_users([email])

		original = frappe.sendmail

		def _boom(*args, **kwargs):
			raise RuntimeError("simulated SMTP failure")

		frappe.sendmail = _boom
		frappe.flags.in_test = False
		try:
			frappe.get_doc(
				{
					"doctype": "User",
					"email": email,
					"first_name": "QRAuto",
					"send_welcome_email": 0,
					"company": COMPANY,
					"roles": [{"role": "Stock User"}],
				}
			).insert(ignore_permissions=True)
		finally:
			frappe.sendmail = original
			frappe.flags.in_test = True

		creds = frappe.get_all(
			"QR Login Credential", filters={"user": email}, pluck="name"
		)
		self.assertEqual(len(creds), 1)
		self.assertEqual(
			frappe.db.get_value("QR Login Credential", creds[0], "status"),
			CREDENTIAL_STATUS_ACTIVE,
		)
		self.assertGreaterEqual(
			frappe.db.count("Error Log", {"method": "QR welcome email failed"}), 1
		)

	def test_resend_reuses_credential(self):
		"""Spec resend: same credential re-mailed, never re-minted."""
		email = "qrtest.flow5@test.local"
		cleanup_test_users([email])

		_create_user(email)
		before = frappe.get_all(
			"QR Login Credential", filters={"user": email}, pluck="name"
		)
		self.assertEqual(len(before), 1)

		_, sent = self._mails(qr_manage.resend_welcome_email, before[0])
		after = frappe.get_all(
			"QR Login Credential", filters={"user": email}, pluck="name"
		)
		self.assertEqual(after, before)
		# QR is shown inline via a Content-ID reference (Gmail-safe).
		self.assertTrue(mail.get("inline_images"))
		self.assertIn('embed="', sent[0]["message"])

		# Non-active credentials refuse resend instead of mailing dead codes.
		frappe.db.set_value(
			"QR Login Credential", before[0], "status", "Revoked", update_modified=False
		)
		with self.assertRaises(frappe.ValidationError):
			qr_manage.resend_welcome_email(before[0])

	def test_qr_image_content_is_login_url(self):
		"""Any-camera scanning: images encode a login URL, not bare text."""
		token = "X" * 43
		content = qr_manage._qr_content(token)
		self.assertIn("/login?qr=ADXQR1.", content)
		self.assertTrue(content.startswith("http"))

	def test_download_endpoint_serves_png(self):
		"""Spec download: permission-gated PNG download, no token exposure."""
		email = "qrtest.flow1@test.local"
		cleanup_test_users([email])
		_create_user(email)
		name = frappe.get_all(
			"QR Login Credential", filters={"user": email}, pluck="name"
		)[0]

		frappe.set_user("Administrator")
		frappe.local.response = frappe._dict()
		qr_manage.download_qr_image(name)
		resp = frappe.local.response
		self.assertEqual(resp["type"], "download")
		self.assertTrue(resp["filename"].endswith(".png"))
		self.assertTrue(resp["filecontent"][:8] == b"\x89PNG\r\n\x1a\n")
