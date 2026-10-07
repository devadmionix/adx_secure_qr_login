// Security dashboard for QR Login.
//
// Reads one endpoint, api/qr_stats.dashboard_data, which is role-gated
// server-side. Every figure on screen comes from that response -- nothing is
// computed here, so the dashboard cannot disagree with the weekly report.

frappe.provide("adx.qr_dashboard");

adx.qr_dashboard.render = function (container) {
	const $wrap = $(container);
	adx.qr_dashboard.destroyCharts();
	$wrap.html('<div class="adx-dash-loading text-muted">' + __("Loading…") + "</div>");

	frappe
		.call({
			method: "adx_secure_qr_login.api.qr_stats.dashboard_data",
			args: adx.qr_dashboard.filters(),
		})
		.then((r) => {
			const msg = (r && r.message) || null;
			if (!msg) {
				$wrap.html(
					'<div class="alert alert-warning">' +
						frappe._("Could not load QR security statistics.") +
						"</div>"
				);
				return;
			}
			$wrap.html(adx.qr_dashboard.template(msg));
			adx.qr_dashboard.bindCardLinks($wrap[0]);
			adx.qr_dashboard.renderCharts($wrap[0], msg);
			adx.qr_dashboard.loadCompanies();
		})
		.catch(() => {
			// A PermissionError here is the expected result for a user without a
			// QR role, so say so plainly rather than showing an empty page.
			$wrap.html(
				'<div class="alert alert-warning">' +
					frappe._("You are not permitted to view QR security statistics.") +
					"</div>"
			);
		});
};

// Display filters of spec 17. These only narrow the view; what a user may see
// at all is decided server-side by the DocType permission query conditions, so
// sending a filter for someone else reveals nothing.
adx.qr_dashboard.filters = function () {
	const read = (id) => {
		const el = document.getElementById(id);
		return el && el.value ? el.value : null;
	};
	return {
		frm: read("adx_qr_dash_from"),
		to: read("adx_qr_dash_to"),
		user: read("adx_qr_dash_user"),
		company: read("adx_qr_dash_company"),
	};
};

adx.qr_dashboard.filterBar = function (wantCompany) {
	const input = (id, placeholder, type) =>
		'<input id="' +
		id +
		'" type="' +
		(type || "text") +
		'" class="form-control" placeholder="' +
		placeholder +
		'" style="height:32px">';

	const wantAttr = wantCompany
		? ' data-want="' + frappe.utils.escape_html(wantCompany) + '"'
		: "";
	const companySelect =
		'<select id="adx_qr_dash_company" class="form-control" style="height:32px"' +
		wantAttr +
		">" +
		'<option value="">' +
		frappe._("All companies") +
		"</option>" +
		"</select>";

	return (
		'<div class="adx-dash-filters" style="margin-bottom:14px">' +
		'<div class="row">' +
		'<div class="col-md-2">' + input("adx_qr_dash_from", frappe._("From"), "date") + "</div>" +
		'<div class="col-md-2">' + input("adx_qr_dash_to", frappe._("To"), "date") + "</div>" +
		'<div class="col-md-3">' + input("adx_qr_dash_user", frappe._("User (email)")) + "</div>" +
		'<div class="col-md-3">' + companySelect + "</div>" +
		'<div class="col-md-2">' +
		'<button class="btn btn-primary btn-sm" style="height:32px" onclick="adx.qr_dashboard.reload()">' +
		frappe._("Apply") +
		"</button> " +
		'<button class="btn btn-default btn-sm" style="height:32px" onclick="adx.qr_dashboard.clearFilters()">' +
		frappe._("Clear") +
		"</button>" +
		"</div></div>" +
		'<div class="row" style="margin-top:8px"><div class="col-md-12">' +
		'<button class="btn btn-xs btn-default" onclick="adx.qr_dashboard.setRange(1)">' +
		frappe._("Today") +
		"</button> " +
		'<button class="btn btn-xs btn-default" onclick="adx.qr_dashboard.setRange(7)">' +
		frappe._("Last 7 days") +
		"</button> " +
		'<button class="btn btn-xs btn-default" onclick="adx.qr_dashboard.setRange(30)">' +
		frappe._("Last 30 days") +
		"</button>" +
		"</div></div></div>"
	);
};

adx.qr_dashboard.reload = function () {
	const el = document.querySelector(".qr-security-dashboard[data-dashboard='adx-qr-security']");
	if (el) adx.qr_dashboard.render(el);
};

adx.qr_dashboard.destroyCharts = function () {
	(adx.qr_dashboard._charts || []).forEach(function (chart) {
		try {
			chart.destroy();
		} catch (e) {
			/* already gone */
		}
	});
	adx.qr_dashboard._charts = [];
};

// Quick ranges set the From/To inputs and reload. The server still decides
// everything; these are conveniences, not permission boundaries.
adx.qr_dashboard.setRange = function (days) {
	const fmt = (d) => d.toISOString().slice(0, 10);
	const to = new Date();
	const frm = new Date();
	if (days === 1) {
		// Today: both ends on the same date.
	} else {
		frm.setDate(frm.getDate() - (days - 1));
	}
	const fromEl = document.getElementById("adx_qr_dash_from");
	const toEl = document.getElementById("adx_qr_dash_to");
	if (fromEl) fromEl.value = fmt(frm);
	if (toEl) toEl.value = fmt(to);
	adx.qr_dashboard.reload();
};

adx.qr_dashboard.clearFilters = function () {
	["adx_qr_dash_from", "adx_qr_dash_to", "adx_qr_dash_user", "adx_qr_dash_company"].forEach(
		(id) => {
			const el = document.getElementById(id);
			if (el) el.value = "";
		}
	);
	adx.qr_dashboard.reload();
};

// Populate the Company dropdown from the companies the viewer may see.
// Falls back to a typed field when the list is unavailable, so filtering
// never breaks for roles without Company read access.
adx.qr_dashboard.loadCompanies = function () {
	const sel = document.getElementById("adx_qr_dash_company");
	if (!sel || sel.tagName !== "SELECT") return;
	const wanted = sel.getAttribute("data-want") || "";

	frappe
		.call({
			method: "frappe.client.get_list",
			args: {
				doctype: "Company",
				fields: ["name"],
				order_by: "name",
				limit_page_length: 100,
			},
		})
		.then((r) => {
			const rows = (r && r.message) || [];
			if (!rows.length) throw new Error("no-companies");
			const el = document.getElementById("adx_qr_dash_company");
			if (!el || el.tagName !== "SELECT") return;
			el.innerHTML =
				'<option value="">' +
				frappe._("All companies") +
				"</option>" +
				rows
					.map(
						(c) =>
							'<option value="' +
							frappe.utils.escape_html(c.name) +
							'">' +
							frappe.utils.escape_html(c.name) +
							"</option>"
					)
					.join("");
			if (wanted) el.value = wanted;
		})
		.catch(() => {
			// Keep a usable typed filter instead of an empty dropdown.
			const el = document.getElementById("adx_qr_dash_company");
			if (!el || el.tagName !== "SELECT") return;
			const input = document.createElement("input");
			input.id = "adx_qr_dash_company";
			input.type = "text";
			input.className = "form-control";
			input.style.height = "32px";
			input.placeholder = frappe._("Company");
			if (wanted) input.value = wanted;
			el.replaceWith(input);
		});
};

adx.qr_dashboard.card = function (label, value, tone, route) {
	// A route makes the card a link into the related list, pre-filtered.
	// No data is exposed by this: the list itself enforces permissions.
	const glyphs = { green: "✓", orange: "!", red: "✕", blue: "●" };
	const inner =
		'<div class="qr-stat-top">' +
		'<div class="qr-stat-value">' +
		frappe.format(value || 0, {"df": null}) +
		"</div>" +
		'<div class="qr-stat-icon" data-tone="' +
		(tone || "grey") +
		'">' +
		(glyphs[tone] || "●") +
		"</div>" +
		"</div>" +
		'<div class="qr-stat-label">' +
		frappe._(label) +
		"</div>";
	const card =
		'<div class="qr-stat-card" data-tone="' +
		(tone || "grey") +
		'">' +
		inner +
		"</div>";
	const wrapped = route
		? '<a href="#" data-route=\'' +
			JSON.stringify(route).replace(/'/g, "&#39;") +
			"' class='qr-stat-link'>" +
			card +
			"</a>"
		: card;
	return (
		'<div class="col-md-4 col-xs-6" style="margin-bottom:12px">' + wrapped + "</div>"
	);
};

adx.qr_dashboard.bindCardLinks = function (container) {
	[...container.querySelectorAll("a.qr-stat-link")].forEach((a) => {
		a.addEventListener("click", (e) => {
			e.preventDefault();
			try {
				const route = JSON.parse(a.getAttribute("data-route"));
				frappe.set_route(route[0], route[1], route[2]);
			} catch (err) {
				/* malformed route: stay put */
			}
		});
	});
};

adx.qr_dashboard.renderCharts = function (container, d) {
	// frappe.Chart ships with the desk bundle. If it is ever unavailable the
	// dashboard degrades to cards and tables rather than failing.
	if (!window.frappe || !frappe.Chart) return;
	adx.qr_dashboard.destroyCharts();
	const mount = (id) => container.querySelector(id);

	const daily = d.daily || [];
	if (daily.length && mount("#adx_qr_chart_activity")) {
		adx.qr_dashboard._charts.push(
			new frappe.Chart("#adx_qr_chart_activity", {
				title: frappe._("Login activity"),
				type: "bar",
				height: 220,
				data: {
					labels: daily.map((r) => r.day),
					datasets: [
						{ name: frappe._("Successful"), values: daily.map((r) => r.successful) },
						{ name: frappe._("Failed"), values: daily.map((r) => r.failed) },
					],
				},
			})
		);
	}

	const c = d.credentials || {};
	const mix = [c.active || 0, c.expired || 0, c.revoked || 0, c.superseded || 0];
	if (mix.some((v) => v > 0) && mount("#adx_qr_chart_mix")) {
		adx.qr_dashboard._charts.push(
			new frappe.Chart("#adx_qr_chart_mix", {
				title: frappe._("Credential status"),
				type: "donut",
				height: 220,
				data: {
					labels: [
						frappe._("Active"),
						frappe._("Expired"),
						frappe._("Revoked"),
						frappe._("Superseded"),
					],
					datasets: [{ values: mix }],
				},
			})
		);
	}
};

adx.qr_dashboard.template = function (d) {
	const c = d.credentials || {};
	const a = d.authentication || {};
	const s = d.security || {};

	const active = a.filters || {};
	const filterBar = adx.qr_dashboard.filterBar(active.company);
	// Re-apply whatever is already set, so the 60s refresh does not wipe a filter.
	["from", "to", "user", "company"].forEach((k) => {
		const el = document.getElementById("adx_qr_dash_" + k);
		if (el && active[{"from": "frm"}[k] || k]) el.value = active[{"from": "frm"}[k] || k];
	});

	const cards = [
		adx.qr_dashboard.card("Active QRs", c.active, "green", [
			"List",
			"QR Login Credential",
			{ status: "Active" },
		]),
		adx.qr_dashboard.card("Expired QRs", c.expired, "orange", [
			"List",
			"QR Login Credential",
			{ status: "Expired" },
		]),
		adx.qr_dashboard.card("Revoked QRs", c.revoked, "red", [
			"List",
			"QR Login Credential",
			{ status: "Revoked" },
		]),
		adx.qr_dashboard.card("Successful QR logins", a.successful_logins, "blue", [
			"List",
			"QR Login Audit",
			{ event: "QR Login Success", success: 1 },
		]),
		adx.qr_dashboard.card("Failed attempts", a.failed_attempts, "red", [
			"List",
			"QR Login Audit",
			{ success: 0 },
		]),
		adx.qr_dashboard.card("Rate-limited attempts", a.rate_limited_attempts, "red"),
		adx.qr_dashboard.card("Security events", s.security_events, "orange"),
	].join("");

	const window_ =
		'<p class="text-muted" style="font-size:12px">' +
		frappe._("Window: {0} to {1}", [
			frappe.datetime.str_to_user((a.window || []).join("") || ""),
		]) +
		"</p>";

	let reasonBlock = '<p class="text-muted">' + frappe._("No failures recorded.") + "</p>";
	if (s.by_reason && Object.keys(s.by_reason).length) {
		const entries = Object.keys(s.by_reason)
			.sort((x, y) => s.by_reason[y] - s.by_reason[x])
			.slice(0, 8);
		const max = Math.max(...entries.map((r) => s.by_reason[r]), 1);
		const tones = {
			RATE_LIMITED: "orange",
			INVALID_CREDENTIAL: "red",
			EXPIRED_CREDENTIAL: "orange",
			REVOKED_CREDENTIAL: "red",
			INACTIVE_USER: "orange",
		};
		reasonBlock = entries
			.map((r) => {
				const pct = Math.max(4, Math.round((s.by_reason[r] / max) * 100));
				const tone = tones[r] || "red";
				return (
					'<div class="adx-reason">' +
					'<div class="adx-reason-head"><span>' +
					frappe._(r.replace(/_/g, " ").toLowerCase()) +
					"</span><strong>" +
					s.by_reason[r] +
					"</strong></div>" +
					'<div class="adx-reason-bar"><span data-tone="' +
					tone +
					'" style="width:' +
					pct +
					'%"></span></div>' +
					"</div>"
				);
			})
			.join("");
	}

	const generated = d.generated_on
		? frappe.datetime.str_to_user(d.generated_on)
		: "";

	return (
		'<div class="adx-dash-head">' +
		'<div class="adx-dash-badge">QR</div>' +
		"<div><div class='adx-dash-title'>" +
		frappe._("Security Overview") +
		"</div><div class='adx-dash-sub'>" +
		frappe._("Live QR credential and login activity") +
		(generated ? " · " + frappe._("Updated {0}", [generated]) : "") +
		"</div></div>" +
		'<button class="btn btn-xs btn-default" style="margin-left:auto" onclick="adx.qr_dashboard.reload()">' +
		frappe._("Refresh") +
		"</button>" +
		"</div>" +
		filterBar +
		'<div class="row">' +
		cards +
		"</div>" +
		'<div class="row"><div class="col-md-6">' +
		'<div class="adx-panel"><h5>' +
		frappe._("Login activity") +
		"</h5>" +
		'<div id="adx_qr_chart_activity"></div></div>' +
		"</div><div class='col-md-6'>" +
		'<div class="adx-panel"><h5>' +
		frappe._("Credential status") +
		"</h5>" +
		'<div id="adx_qr_chart_mix"></div></div>' +
		"</div></div>" +
		'<div class="row"><div class="col-md-6">' +
		'<div class="adx-panel"><h5>' +
		frappe._("Failure reasons") +
		"</h5>" +
		reasonBlock +
		'</div></div><div class="col-md-6">' +
		'<div class="adx-panel"><h5>' +
		frappe._("Recent failures") +
		"</h5>" +
		adx.qr_dashboard.auditTable(d.recent_failures || []) +
		"</div></div></div>" +
		window_
	);
};

adx.qr_dashboard.auditTable = function (rows) {
	if (!rows.length) {
		return '<p class="text-muted">' + frappe._("Nothing to show.") + "</p>";
	}
	const body = rows
		.map((r) => {
			const tone = r.reason_code === "RATE_LIMITED" ? "orange" : "red";
			return (
				"<tr>" +
				"<td>" +
				(r.user || frappe._("unknown")) +
				"</td>" +
				"<td><span class='indicator " +
				tone +
				"'>" +
				frappe._(String(r.event || "").toLowerCase()) +
				"</span></td>" +
				"<td>" +
				frappe.datetime.str_to_user(r.occurred_on || "") +
				"</td>" +
				"<td class='text-muted' style='font-size:11px'>" +
				(r.ip_address || "") +
				"</td>" +
				"</tr>"
			);
		})
		.join("");

	return (
		"<table class='table table-sm' style='max-width:520px'>" +
		"<thead><tr><th>" +
		frappe._("User") +
		"</th><th>" +
		frappe._("Outcome") +
		"</th><th>" +
		frappe._("When") +
		"</th><th>" +
		frappe._("IP") +
		"</th></tr></thead><tbody>" +
		body +
		"</tbody></table>"
	);
};

frappe.ready(function () {
	const $target = $(".qr-security-dashboard[data-dashboard='adx-qr-security']");
	if (!$target.length) return;

	const target = $target[0];
	adx.qr_dashboard.render(target);

	// Keep the view current without a manual refresh, but stop when hidden.
	let timer = null;
	const start = () => {
		if (timer) return;
		timer = setInterval(() => {
			if (!document.hidden) adx.qr_dashboard.render(target);
		}, 60000);
	};
	const stop = () => {
		if (timer) clearInterval(timer);
		timer = null;
	};

	$(document).on("visibilitychange", () => (document.hidden ? stop() : start()));
	$(window).on("beforeunload", stop);
	start();
});
