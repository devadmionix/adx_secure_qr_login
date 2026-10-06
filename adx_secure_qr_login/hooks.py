app_name = "adx_secure_qr_login"
app_title = "Secure QR Login"
app_publisher = "ADmionix Solutions "
app_description = "Secure QR Login"
app_email = "sales@admionixsolutions.com"
app_license = "mit"

# Apps
# ------------------

# QR login depends on ERPNext User/Role/Company semantics and on the stock
# Frappe permission engine. Declared so it cannot be installed against a bare
# Frappe site where roles like "Sales User" do not exist.
required_apps = ["frappe", "erpnext"]

# Each item in the list will be shown as an app in the apps page
add_to_apps_screen = [
	{
		"name": "adx_secure_qr_login",
		"logo": "/assets/adx_secure_qr_login/logo.svg",
		"title": "Secure QR Login",
		"route": "/desk/secure-qr-login",
	}
]

# Includes in <head>
# ------------------

# Desk bundle for the credential / audit views.
# Phase 2 ships no desk JS yet; the key is reserved so later phases do not have
# to touch hooks.py again.
app_include_js = ["adx_secure_qr_login.bundle.js"]
app_include_css = "/assets/adx_secure_qr_login/css/qr_dashboard.css"

# include js, css files in header of web template
#
# These fire on every website page, including /login
# (frappe/website/doctype/website_settings/website_settings.py:231 renders
# `web_include_js` at templates/base.html:105). They are how the QR login option
# reaches the login page without editing frappe/www/login.html: the script injects
# its own UI into the DOM at runtime.
web_include_css = "/assets/adx_secure_qr_login/css/qr_login.css"
web_include_js = "/assets/adx_secure_qr_login/js/qr_login_scan.js"

# include custom scss in every website theme (without file extension ".scss")
# website_theme_scss = "adx_secure_qr_login/public/scss/website"

# include js, css files in header of web form
# webform_include_js = {"doctype": "public/js/doctype.js"}
# webform_include_css = {"doctype": "public/css/doctype.css"}

# include js in page
# page_js = {"page" : "public/js/file.js"}

# include js in doctype views
doctype_js = {
	"QR Login Credential": "public/js/qr_login_credential.js",
}
# doctype_list_js = {"doctype" : "public/js/doctype_list.js"}
# doctype_tree_js = {"doctype" : "public/js/doctype_tree.js"}
# doctype_calendar_js = {"doctype" : "public/js/doctype_calendar.js"}

# Svg Icons
# ------------------
# include app icons in desk
# app_include_icons = "adx_secure_qr_login/public/icons.svg"

# Home Pages
# ----------

# application home page (will override Website Settings)
# home_page = "login"

# website user home page (by Role)
# role_home_page = {
# 	"Role": "home_page"
# }

# Generators
# ----------

# automatically create page for each record of this doctype
# website_generators = ["Web Page"]

# automatically load and sync documents of this doctype from downstream apps
# importable_doctypes = [doctype_1]

# Jinja
# ----------

# add methods and filters to jinja environment
# jinja = {
# 	"methods": "adx_secure_qr_login.utils.jinja_methods",
# 	"filters": "adx_secure_qr_login.utils.jinja_filters"
# }

# Installation
# ------------

# before_install = "adx_secure_qr_login.install.before_install"
# after_install = "adx_secure_qr_login.install.after_install"

# Uninstallation
# ------------

# before_uninstall = "adx_secure_qr_login.uninstall.before_uninstall"
# after_uninstall = "adx_secure_qr_login.uninstall.after_uninstall"

# Integration Setup
# ------------------
# To set up dependencies/integrations with other apps
# Name of the app being installed is passed as an argument

# before_app_install = "adx_secure_qr_login.utils.before_app_install"
# after_app_install = "adx_secure_qr_login.utils.after_app_install"

# Integration Cleanup
# -------------------
# To clean up dependencies/integrations with other apps
# Name of the app being uninstalled is passed as an argument

# before_app_uninstall = "adx_secure_qr_login.utils.before_app_uninstall"
# after_app_uninstall = "adx_secure_qr_login.utils.after_app_uninstall"

# Build
# ------------------
# To hook into the build process

# after_build = "adx_secure_qr_login.build.after_build"

# Desk Notifications
# ------------------
# See frappe.core.notifications.get_notification_config

# notification_config = "adx_secure_qr_login.notifications.get_notification_config"

# Awesome Bar
# -----------
# Extra search results: list of dicts with label, description, route, index.
# route: ["List", "ToDo"], "/desk/docs/some/page", or "https://example.com"
# awesomebar_search = ["adx_secure_qr_login.search.awesomebar_results"]

# Permissions
# -----------
# Permissions evaluated in scripted ways

# `if_owner` is the wrong scoping tool for QR Login Credential: the owner is
# whoever issued the credential, not the user it authenticates. These hooks
# scope rows by subject instead. See permissions/credential_conditions.py.
permission_query_conditions = {
	"QR Login Credential": "adx_secure_qr_login.permissions.credential_conditions.get_permission_query_conditions",
	# Company-isolate the core User list/link field.
	"User": "adx_secure_qr_login.permissions.user_conditions.get_permission_query_conditions",
	# The audit trail is security evidence. Administrators and QR Admins see all;
	# QR Managers see only rows for users they may manage; ordinary desk users
	# see nothing. See permissions/audit_conditions.py.
	"QR Login Audit": "adx_secure_qr_login.permissions.audit_conditions.get_permission_query_conditions",
	# Weekly aggregates are admin-only. See permissions/weekly_report_conditions.py.
	"Weekly Security Report": "adx_secure_qr_login.permissions.weekly_report_conditions.get_permission_query_conditions",
}

has_permission = {
	"QR Login Credential": "adx_secure_qr_login.permissions.credential_conditions.has_permission",
	"QR Login Audit": "adx_secure_qr_login.permissions.audit_conditions.has_permission",
	"Weekly Security Report": "adx_secure_qr_login.permissions.weekly_report_conditions.has_permission",
	# Company-isolate the core User list/link field at the same backend level,
	# otherwise a Company A user can see Company B users.
	"User": "adx_secure_qr_login.permissions.user_conditions.has_permission",
}

# Document Events
# ---------------
# Hook on document methods and events

# Supplies the transient `qr_image_data` attribute that the card print format
# renders. Deliberately not a field: it must never appear in a form response.
doc_events = {
	"QR Login Credential": {
		"before_print": "adx_secure_qr_login.security.print_hooks.before_print_card",
	},
	# Spec 14 USER_DISABLED / SESSION_REVOKED. A disabled account keeps its live
	# Frappe sessions otherwise, which on a QR login is the whole point of
	# disabling it. `before_save` snapshots the stored flag so `on_update` can see
	# the transition -- User is saved by many unrelated routes. (There is no
	# `before_update` hook in Frappe: run_before_save_methods only runs
	# before_validate / validate / before_save / before_submit.)
	"User": {
		"before_save": (
			"adx_secure_qr_login.security.session_events.capture_previous_state"
		),
		"on_update": "adx_secure_qr_login.security.session_events.record_user_disabled",
		# Auto-issue a QR credential + welcome email for newly created users
		# (opt-in setting, System Users with a company only).
		"after_insert": "adx_secure_qr_login.api.qr_manage.issue_credential_for_new_user",
	},
}

# Scheduled Tasks
# ---------------

# The weekly report runs Monday 08:00 and summarises the *previous*
# Monday-Sunday, so it never races the week it is reporting on. The window is
# derived from the current date inside `previous_week()`, so the cron entry only
# decides when the job fires.
#
# `refresh_expiry_status` keeps list views and dashboard counts honest. It is NOT
# a security control: validation.py recomputes expiry on every authentication
# attempt, so a lapsed credential is rejected even if this job has not run.
scheduler_events = {
	"cron": {
		# Persistent weekly report (Feature 8): Monday 00:05 stores the previous
		# Monday-Sunday as a `Weekly Security Report` record. Duplicate-safe.
		"5 0 * * 1": [
			"adx_secure_qr_login.security.weekly_report.generate_for_previous_week",
		],
		"0 8 * * 1": [
			"adx_secure_qr_login.reports.weekly_security_report.send_weekly_report",
		],
		"7 */2 * * *": [
			"adx_secure_qr_login.tasks.refresh_expiry_status",
		],
	},
	"hourly": [
		"adx_secure_qr_login.tasks.refresh_expiry_status",
	],
	"daily": [
		"adx_secure_qr_login.tasks.purge_expired_audit",
	],
}

# Fixtures
# --------
# Ships the `Company` custom field on User (multi-company QR login gate).
# A Custom Field never touches Frappe/ERPNext core files; it syncs into any
# site on migrate. Filtered to this app's field so unrelated site
# customizations are never exported.
fixtures = [
	{
		"dt": "Custom Field",
		"filters": [["name", "=", "User-company"]],
	}
]

# Testing
# -------

# before_tests = "adx_secure_qr_login.install.before_tests"

# Extend DocType Class
# ------------------------------
#
# Specify custom mixins to extend the standard doctype controller.
# extend_doctype_class = {
# 	"Task": "adx_secure_qr_login.custom.task.CustomTaskMixin"
# }

# Overriding Methods
# ------------------------------
#
# override_whitelisted_methods = {
# 	"frappe.desk.doctype.event.event.get_events": "adx_secure_qr_login.event.get_events"
# }
#
# each overriding function accepts a `data` argument;
# generated from the base implementation of the doctype dashboard,
# along with any modifications made in other Frappe apps
# override_doctype_dashboards = {
# 	"Task": "adx_secure_qr_login.task.get_dashboard_data"
# }

# exempt linked doctypes from being automatically cancelled
#
# auto_cancel_exempted_doctypes = ["Auto Repeat"]

# Ignore links to specified DocTypes when deleting documents
# -----------------------------------------------------------

# ignore_links_on_delete = ["Communication", "ToDo"]

# Request Events
# ----------------
# before_request = ["adx_secure_qr_login.utils.before_request"]
# after_request = ["adx_secure_qr_login.utils.after_request"]

# Job Events
# ----------
# before_job = ["adx_secure_qr_login.utils.before_job"]
# after_job = ["adx_secure_qr_login.utils.after_job"]

# User Data Protection
# --------------------

# user_data_fields = [
# 	{
# 		"doctype": "{doctype_1}",
# 		"filter_by": "{filter_by}",
# 		"redact_fields": ["{field_1}", "{field_2}"],
# 		"partial": 1,
# 	},
# 	{
# 		"doctype": "{doctype_2}",
# 		"filter_by": "{filter_by}",
# 		"partial": 1,
# 	},
# 	{
# 		"doctype": "{doctype_3}",
# 		"strict": False,
# 	},
# 	{
# 		"doctype": "{doctype_4}"
# 	}
# ]

# Authentication and authorization
# --------------------------------

# auth_hooks = [
# 	"adx_secure_qr_login.auth.validate"
# ]

# Automatically update python controller files with type annotations for this app.
# export_python_type_annotations = True

# default_log_clearing_doctypes = {
# 	"Logging DocType Name": 30  # days to retain logs
# }

# Translation
# ------------
# List of apps whose translatable strings should be excluded from this app's translations.
# ignore_translatable_strings_from = []

