// Copyright (c) 2026, ADmionix Solutions
// License: MIT

// My QR: the signed-in user's own QR credential.
//
// Every call is parameterless on the user: the server acts on the session user
// only, so this page cannot be pointed at another account. Generate / Revoke
// appear only when the matching QR Security Settings switch is on, and the
// server re-checks the same switch. View / Download / Print appear only when
// "Allow Users To Download Own QR" is on (the server enforces that too).
//
// No token is ever shown as text. The QR image is displayed either once, right
// after generation, or from the stored image when downloads are permitted.

frappe.pages["my-qr"].on_page_load = function (wrapper) {
	const page = frappe.ui.make_app_page({
		parent: wrapper,
		title: __("My QR"),
		single_column: true,
	});

	const api = "adx_secure_qr_login.api";
	const $body = $('<div class="adx-my-qr" style="margin: var(--margin-md);max-width:560px;"></div>').appendTo(
		page.body.empty()
	);

	const esc = frappe.utils.escape_html;
	const fmt = (d) => (d ? frappe.datetime.str_to_user(String(d).split(" ")[0]) : "—");
	let state = null;
	let shown_image = null; // data URI, only held in memory

	const load = () =>
		frappe.call({ method: `${api}.qr_my.get_my_qr`, type: "GET" }).then((r) => {
			state = r.message;
			render();
		});

	const row = (label, value) =>
		`<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border-color);">
			<span class="text-muted">${label}</span><span>${value}</span></div>`;

	const render = () => {
		const s = state;
		const a = s.active;
		let html = "";

		if (!s.eligible) {
			html += `<div class="alert alert-warning">${esc(s.reason || "")}</div>`;
		}

		html += `<div class="frappe-card" style="padding:var(--padding-lg);margin-bottom:var(--margin-md);">
			${row(__("Status"), a ? `<span class="indicator-pill green">${__("Active")}</span>` : `<span class="indicator-pill gray">${__("No active QR")}</span>`)}
			${row(__("Issued"), esc(fmt(a && a.issued_on)))}
			${row(__("Expires"), esc(fmt(a && a.expires_on)))}
			${row(__("Last used"), esc(fmt(a && a.last_used)))}
		</div>`;

		if (shown_image) {
			html += `<div style="text-align:center;margin-bottom:var(--margin-md);">
				<img class="adx-my-qr-img" src="${shown_image}" alt="${__("My login QR code")}"
					style="width:240px;height:240px;border:1px solid var(--border-color);border-radius:8px;padding:8px;background:#fff;" />
			</div>`;
		}

		html += `<div class="adx-my-qr-actions" style="display:flex;flex-wrap:wrap;gap:8px;">`;
		if (a && s.can_download) {
			html += `<button class="btn btn-default btn-sm" data-act="view">${__("View QR")}</button>
				<button class="btn btn-default btn-sm" data-act="download">${__("Download QR")}</button>
				<button class="btn btn-default btn-sm" data-act="print">${__("Print QR")}</button>`;
		}
		if (s.can_generate) {
			html += `<button class="btn btn-primary btn-sm" data-act="generate">${__("Generate My QR")}</button>`;
		}
		if (s.can_revoke) {
			html += `<button class="btn btn-danger btn-sm" data-act="revoke">${__("Revoke My QR")}</button>`;
		}
		html += `</div>`;

		if (a && !s.can_download) {
			html += `<p class="text-muted small" style="margin-top:var(--margin-md);">${__(
				"Your administrator has not allowed re-downloading your QR. Ask them to re-issue it if you need a copy."
			)}</p>`;
		}
		if (!a && !s.can_generate && s.eligible) {
			html += `<p class="text-muted small" style="margin-top:var(--margin-md);">${__(
				"You do not have an active QR. Ask your administrator to issue one."
			)}</p>`;
		}

		$body.html(html);
		$body.find("[data-act]").on("click", function () {
			actions[$(this).data("act")]();
		});
	};

	const stored_image = () =>
		frappe
			.call({
				method: `${api}.qr_manage.get_qr_data_uri`,
				args: { credential: state.active.name },
				type: "GET",
			})
			.then((r) => r.message);

	const actions = {
		view() {
			stored_image().then((uri) => {
				shown_image = uri || null;
				if (!uri) frappe.msgprint(__("No stored QR image is available. Generate a new one."));
				render();
			});
		},
		download() {
			window.location.href = `/api/method/${api}.qr_manage.download_qr_image?credential=${encodeURIComponent(
				state.active.name
			)}`;
		},
		print() {
			stored_image().then((uri) => {
				if (!uri) return;
				const w = window.open("", "_blank");
				if (!w) return;
				w.document.write(
					`<html><head><title>${esc(__("My QR"))}</title></head><body style="text-align:center;font-family:sans-serif;">
					<h3>${esc(frappe.session.user_fullname || frappe.session.user)}</h3>
					<img src="${uri}" style="width:320px;height:320px;" />
					<p>${esc(__("Expires"))}: ${esc(fmt(state.active.expires_on))}</p>
					<script>window.onload=function(){window.print();}<\/script></body></html>`
				);
				w.document.close();
			});
		},
		generate() {
			const run = () =>
				frappe
					.call({ method: `${api}.qr_my.generate_my_qr`, freeze: true })
					.then((r) => {
						shown_image = (r.message && r.message.qr_svg) || null;
						frappe.show_alert({ message: __("Your QR was generated"), indicator: "green" });
						return load();
					});
			if (state.active) {
				frappe.confirm(__("You already have an active QR. Generate another one?"), run);
			} else {
				run();
			}
		},
		revoke() {
			const dialog = new frappe.ui.Dialog({
				title: __("Revoke My QR"),
				fields: [
					{
						fieldtype: "HTML",
						fieldname: "message",
						options: `<p><strong>${__(
							"Are you sure you want to revoke your QR credential?"
						)}</strong></p>
						<p class="text-muted">${__(
							"This credential will no longer be usable for QR login."
						)}</p>`,
					},
				],
				primary_action_label: __("Revoke"),
				primary_action: () => {
					dialog.hide();
					// The server acts on the signed-in user and re-checks that the
					// credential is theirs; nothing here names another account.
					frappe
						.call({
							method: `${api}.qr_my.revoke_my_qr`,
							args: { credential: state.active.name },
							freeze: true,
						})
						.then(() => {
							shown_image = null;
							frappe.show_alert({ message: __("Your QR was revoked"), indicator: "green" });
							return load();
						});
				},
				secondary_action_label: __("Cancel"),
				secondary_action: () => dialog.hide(),
			});
			dialog.show();
		},
	};

	page.set_secondary_action(__("Refresh"), () => load(), "refresh");
	load();
};
