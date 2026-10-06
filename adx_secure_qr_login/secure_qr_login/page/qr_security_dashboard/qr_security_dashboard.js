// Copyright (c) 2026, ADmionix Solutions
// License: MIT

// Desk Page hosting the QR security dashboard.
//
// Rendering itself lives in the desk bundle (`public/js/qr_dashboard.js`,
// `adx.qr_dashboard.render`), shared with any other mount point, so the page
// script only owns layout, refresh timing, and access messaging. All figures
// come from the role-gated `qr_stats.dashboard_data` endpoint.

frappe.pages["qr-security-dashboard"].on_page_load = function (wrapper) {
	const page = frappe.ui.make_app_page({
		parent: wrapper,
		title: __("QR Security Dashboard"),
		single_column: true,
	});

	$(`
		<div class="qr-security-dashboard" data-dashboard="adx-qr-security"
			style="margin: var(--margin-md);"></div>
	`).appendTo(page.body.empty());

	page.dashboard_target = page.body.find(
		".qr-security-dashboard[data-dashboard='adx-qr-security']"
	)[0];

	// Live view, paused while the tab is hidden or the route changes.
	let timer = null;
	const render = () => {
		if (page.dashboard_target && window.adx && adx.qr_dashboard) {
			adx.qr_dashboard.render(page.dashboard_target);
		}
	};
	const start = () => {
		if (timer) return;
		timer = setInterval(() => {
			if (!document.hidden) render();
		}, 60000);
	};
	const stop = () => {
		if (timer) clearInterval(timer);
		timer = null;
	};

	$(wrapper).bind("show", () => {
		render();
		start();
	});
	$(wrapper).bind("hide", stop);
	$(window).on("beforeunload", stop);
};
