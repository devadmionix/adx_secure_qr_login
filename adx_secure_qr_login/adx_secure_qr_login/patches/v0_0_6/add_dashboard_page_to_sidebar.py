"""Link the QR Security Dashboard page into the desk sidebar.

The explicit "Secure QR Login" sidebar (v0_0_5) replaces Frappe's
auto-generated one, so the new Page needs an explicit link or it is reachable
only by URL/search.

The implementation now lives in `desktop.ensure_dashboard_link()`, which is also
called from `after_migrate`. That is not redundant: `bench migrate` regenerates
`Workspace Sidebar` from the module, which drops a link added once by a patch.
Re-applying on every migrate keeps the shortcut present on existing sites.
"""

from adx_secure_qr_login.desktop import ensure_dashboard_link


def execute():
	ensure_dashboard_link()
