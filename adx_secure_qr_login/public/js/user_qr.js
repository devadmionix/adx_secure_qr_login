// Copyright (c) 2026, ADmionix Solutions
// License: MIT

// User form: QR Login status block, "Generate QR" and "View QR Credentials".
//
// Nothing here mints or authorizes anything. "Generate QR" calls
// `qr_manage.generate_user_qr`, a thin wrapper over the existing
// `generate_credential`, which re-checks permission, company and status on the
// server. Hiding the buttons for non-managers is only a UI convenience; calling
// the API directly is refused the same way.
//
// No token is ever rendered as text. The QR image appears once, right after
// generation, exactly as it does for the credential flow.

frappe.ui.form.on("User", {
	refresh(frm) {
		adx_user_qr.render(frm);
	},

	qr_generate_button(frm) {
		adx_user_qr.generate(frm);
	},

	qr_view_credentials_button(frm) {
		frappe.route_options = { user: frm.doc.name };
		frappe.set_route("List", "QR Login Credential");
	},
});

window.adx_user_qr = {
	api: "adx_secure_qr_login.api.qr_manage",

	field(frm) {
		return frm.fields_dict.qr_login_info;
	},

	// Fetch the summary and (re)draw the block. Buttons are hidden until the
	// server confirms the viewer may manage this user.
	render(frm) {
		const info = this.field(frm);
		if (!info) return;

		const show_buttons = (visible) => {
			["qr_generate_button", "qr_view_credentials_button"].forEach((f) => {
				if (frm.fields_dict[f]) frm.toggle_display(f, visible);
			});
		};
		show_buttons(false);

		if (frm.is_new() || frm.doc.user_type !== "System User") return;

		frappe
			.call({
				method: `${this.api}.get_user_qr_summary`,
				args: { user: frm.doc.name },
				type: "GET",
			})
			.then((r) => {
				const s = r && r.message;
				if (!s || !s.visible) {
					info.$wrapper.empty();
					return;
				}
				frm.__adx_qr_summary = s;
				info.$wrapper.html(this.html(s));
				show_buttons(!!s.can_manage);
			});
	},

	html(s) {
		const yes = __("Yes");
		const no = __("No");
		const expires = s.expires_on
			? frappe.datetime.str_to_user(s.expires_on)
			: "—";
		const row = (label, value) =>
			`<div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid var(--border-color);">
				<span class="text-muted">${__(label)}</span>
				<span>${value}</span>
			</div>`;
		const status = s.active_count
			? `<span class="indicator-pill green">${__("Active")}</span>`
			: `<span class="indicator-pill gray">${__("No active QR")}</span>`;

		let warning = "";
		if (s.company_required && !s.company) {
			warning = `<div class="text-warning small" style="margin-top:6px;">${__(
				"No Company set: QR login is blocked until a Company is assigned."
			)}</div>`;
		}

		return `<div class="adx-user-qr" style="max-width:420px;">
			${row("QR Login Enabled", s.qr_login_enabled ? yes : no)}
			${row("Active Credential", s.active_count ? yes : no)}
			${row("Active QR Credentials", frappe.utils.escape_html(String(s.active_count)))}
			${row("Expiration", frappe.utils.escape_html(expires))}
			${row("Status", status)}
			${warning}
		</div>`;
	},

	generate(frm) {
		const s = frm.__adx_qr_summary || {};

		const run = () =>
			frappe
				.call({
					method: `${this.api}.generate_user_qr`,
					args: { user: frm.doc.name },
					freeze: true,
					freeze_message: __("Generating QR..."),
				})
				.then((r) => {
					if (r && r.message) this.show_result(frm, r.message);
				});

		if (s.active_count) {
			frappe.confirm(
				__(
					"{0} already has an active QR credential. Generate another one?",
					[frappe.utils.escape_html(frm.doc.full_name || frm.doc.name)]
				),
				run
			);
		} else {
			run();
		}
	},

	// The QR image is shown once. Email goes through the existing
	// resend_welcome_email endpoint (stored PNG, never the token).
	show_result(frm, res) {
		const expires = res.expires_on
			? frappe.datetime.str_to_user(res.expires_on)
			: "";

		const dialog = new frappe.ui.Dialog({
			title: __("QR Credential Generated"),
			fields: [
				{
					fieldtype: "HTML",
					fieldname: "qr",
					options: `<div style="text-align:center;">
						<img src="${res.qr_svg}" alt="${__("Login QR code")}"
							style="width:220px;height:220px;border:1px solid var(--border-color);border-radius:8px;padding:8px;background:#fff;" />
						<p class="text-muted small" style="margin-top:8px;">
							${__("Expires on {0}", [frappe.utils.escape_html(expires)])}
						</p>
						<p class="text-muted small">${frappe.utils.escape_html(res.notice || "")}</p>
					</div>`,
				},
			],
			primary_action_label: __("Email QR to User"),
			primary_action: () => {
				frappe
					.call({
						method: `${this.api}.resend_welcome_email`,
						args: { credential: res.credential },
						freeze: true,
					})
					.then((r) => {
						if (r && r.message && r.message.mailed) {
							frappe.show_alert({
								message: __("QR emailed to {0}", [r.message.user]),
								indicator: "green",
							});
						}
					});
			},
			secondary_action_label: __("Close"),
			secondary_action: () => dialog.hide(),
		});
		dialog.on_hide = () => this.refresh_form(frm);
		dialog.show();
	},

	// Reload the doc unless there are unsaved edits we would throw away.
	refresh_form(frm) {
		if (frm.is_dirty()) {
			this.render(frm);
		} else {
			frm.reload_doc();
		}
	},
};
