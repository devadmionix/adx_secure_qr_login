// Desk bundle for Secure QR Login.
//
// Phase 2 (application foundation) ships no desk behaviour yet, so this bundle is
// intentionally empty of imports. It exists so that `app_include_js` in
// hooks.py resolves to a real, buildable entry point; later phases add imports
// here rather than editing hooks.py again.
//
// esbuild resolves relative imports, so any new script dropped under this
// directory is picked up by adding a single `import "./<name>";` line.
//
import "./qr_dashboard.js";
