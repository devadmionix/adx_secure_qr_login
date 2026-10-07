"""The weekly report email carries a PDF of the report.

Run with:

    bench --site <site> run-tests --app adx_secure_qr_login \
          --module adx_secure_qr_login.tests.test_weekly_report_pdf
"""

from unittest import mock

import frappe
from frappe.tests.utils import FrappeTestCase

from adx_secure_qr_login.reports import weekly_security_report as wsr
from adx_secure_qr_login.secure_qr_login.constants import EVENT_INVALID_CREDENTIAL, EVENT_LOGIN_SUCCESS


class TestWeeklyReportPDF(FrappeTestCase):
	FRM, TO = "2033-05-02", "2033-05-08"

	def setUp(self):
		frappe.set_user("Administrator")
		self._wipe()
		for event, when, ok, reason in (
			(EVENT_LOGIN_SUCCESS, "2033-05-03 09:00:00", 1, "OK"),
			(EVENT_INVALID_CREDENTIAL, "2033-05-04 10:00:00", 0, "INVALID_CREDENTIAL"),
			(EVENT_INVALID_CREDENTIAL, "2033-05-04 10:05:00", 0, "REPLAY_DETECTED"),
		):
			frappe.get_doc(
				{
					"doctype": "QR Login Audit",
					"event": event,
					"occurred_on": when,
					"success": ok,
					"reason_code": reason,
					"ip_address": "10.1.1.1",
					"actor": "Administrator",
					"details": "token=SHOULD-NEVER-APPEAR",
					"user_agent": "Mozilla/5.0 secret-agent",
				}
			).insert(ignore_permissions=True)
		frappe.db.commit()

	def tearDown(self):
		self._wipe()

	def _wipe(self):
		frappe.db.sql(
			"delete from `tabQR Login Audit` where occurred_on >= %s and occurred_on < %s",
			("2033-05-02", "2033-05-09"),
		)
		frappe.db.commit()

	def test_pdf_html_is_the_audit_log_layout(self):
		html = wsr.build_pdf_html(self.FRM, self.TO)
		for expected in (
			"Login Audit Log",
			"3 event(s) from 2033-05-02 to 2033-05-08",
			"Total events",
			"Failed / refused",
			"Blocked replays",
			"Login attempts",
			"Admin events",
			"Credential",
			"IP Address",
			"Token already used.",
			"10.1.1.1",
		):
			self.assertIn(expected, html)

	def test_pdf_html_has_no_secrets(self):
		html = wsr.build_pdf_html(self.FRM, self.TO)
		for forbidden in ("token_hash", "secret-agent", "SHOULD-NEVER-APPEAR", "one_time"):
			self.assertNotIn(forbidden, html)

	def test_build_pdf_returns_a_pdf(self):
		pdf = wsr.build_pdf(self.FRM, self.TO)
		self.assertTrue(pdf and pdf.startswith(b"%PDF"))

	def test_every_page_has_company_header_and_page_numbers(self):
		import io

		from pypdf import PdfReader

		pdf = wsr.build_pdf(self.FRM, self.TO)
		pages = PdfReader(io.BytesIO(pdf)).pages
		for number, page in enumerate(pages, start=1):
			text = page.extract_text()
			self.assertIn(f"Page {number} / {len(pages)}", text)
			self.assertIn(wsr._company_label(), text)

	def test_unidentified_login_attempt_is_not_shown_as_admin(self):
		html = wsr.build_pdf_html(self.FRM, self.TO)
		self.assertIn("Unknown", html)

	def test_email_is_sent_with_pdf_attachment(self):
		sent = {}
		with mock.patch.object(wsr, "send_immediately", lambda **kw: sent.update(kw)), mock.patch.object(
			wsr, "report_recipients", return_value=["someone@test.local"]
		):
			result = wsr.send_report_now("2033-05-11")

		self.assertEqual(result["status"], "sent")
		self.assertTrue(result["pdf_attached"])
		attachment = sent["attachments"][0]
		self.assertTrue(attachment["fname"].endswith(".pdf"))
		self.assertTrue(attachment["fcontent"].startswith(b"%PDF"))

	def test_email_still_goes_out_if_pdf_fails(self):
		sent = {}
		with mock.patch.object(wsr, "send_immediately", lambda **kw: sent.update(kw)), mock.patch.object(
			wsr, "report_recipients", return_value=["someone@test.local"]
		), mock.patch.object(wsr, "build_pdf", return_value=None):
			result = wsr.send_report_now("2033-05-11")

		self.assertEqual(result["status"], "sent")
		self.assertFalse(result["pdf_attached"])
		self.assertIsNone(sent["attachments"])
