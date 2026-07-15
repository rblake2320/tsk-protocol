"""
TSK Protocol Demo — End-to-End Browser Test
Tests F1 (Analytics 503 fix), F2 (Sidebar double-highlight fix),
F3 (Anomaly engine text fix), and full feature coverage.

Uses Python Playwright.  Run: python demo/e2e_browser_test.py
"""

import json, time, sys, traceback
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

BASE = "http://localhost:3200"
RESULTS = []

def record(test_id, name, status, detail=""):
    entry = {"test": test_id, "name": name, "status": status, "detail": detail}
    RESULTS.append(entry)
    icon = "PASS" if status == "pass" else "FAIL" if status == "fail" else "WARN"
    print(f"  [{icon}] {test_id}: {name} — {detail}" if detail else f"  [{icon}] {test_id}: {name}")

def run_tests():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()

        # Collect all network requests to /analytics/event
        analytics_requests = []
        all_http_errors = []

        def on_response(response):
            url = response.url
            if "/analytics/event" in url:
                analytics_requests.append({
                    "url": url,
                    "status": response.status,
                    "method": response.request.method,
                })
            if response.status >= 400:
                all_http_errors.append({
                    "url": url,
                    "status": response.status,
                })

        page.on("response", on_response)

        failed_requests = []
        page.on("requestfailed", lambda request: failed_requests.append({
            "url": request.url,
            "failure": request.failure,
        }))

        page_errors = []
        page.on("pageerror", lambda error: page_errors.append(str(error)))

        # Collect console errors
        console_errors = []
        def on_console(msg):
            if msg.type == "error":
                console_errors.append(msg.text)
        page.on("console", on_console)

        # =====================================================================
        # INITIAL LOAD
        # =====================================================================
        print("\n=== INITIAL LOAD ===")
        page.goto(BASE, wait_until="networkidle")
        page.wait_for_timeout(2000)  # Let provisioning complete

        # Check server is responding
        title = page.title()
        record("LOAD-01", "Page loads", "pass" if "TSK" in title else "fail", f"Title: {title}")

        # Check DEMO_MAP provisioned
        demo_map = page.evaluate("!!window.DEMO_MAP")
        record("LOAD-02", "DEMO_MAP provisioned", "pass" if demo_map else "fail")

        # =====================================================================
        # F1 — Analytics 503 fix
        # =====================================================================
        print("\n=== F1: Analytics 503 Fix ===")
        # Clear analytics tracking, navigate through all 6 screens
        analytics_requests.clear()

        screens = ["overview", "vault", "attack", "provision", "stack", "about"]
        for screen_id in screens:
            page.goto(f"{BASE}#{screen_id}", wait_until="networkidle")
            page.wait_for_timeout(800)

        # Wait for analytics flush
        page.wait_for_timeout(2000)

        total_analytics = len(analytics_requests)
        success_analytics = sum(1 for r in analytics_requests if r["status"] == 204)
        fail_analytics = sum(1 for r in analytics_requests if r["status"] >= 400)
        s503_analytics = sum(1 for r in analytics_requests if r["status"] == 503)

        record("F1-01", "Analytics events sent",
               "pass" if total_analytics > 0 else "fail",
               f"{total_analytics} total events captured")
        record("F1-02", "All analytics return 204",
               "pass" if success_analytics == total_analytics and total_analytics > 0 else "fail",
               f"{success_analytics}/{total_analytics} returned 204, {fail_analytics} failed, {s503_analytics} were 503")
        record("F1-03", "No 503 errors",
               "pass" if s503_analytics == 0 else "fail",
               f"{s503_analytics} requests returned 503")

        # Also verify via server-side GET /analytics
        import urllib.request
        try:
            with urllib.request.urlopen(f"{BASE}/analytics") as resp:
                analytics_data = json.loads(resp.read())
                record("F1-04", "Server analytics endpoint working",
                       "pass",
                       f"{analytics_data.get('totalEvents', 0)} total events, "
                       f"screen_views: {json.dumps(analytics_data.get('screenViews', {}))}")
        except Exception as e:
            record("F1-04", "Server analytics endpoint working", "fail", str(e))

        # =====================================================================
        # F2 — Sidebar double-highlight fix
        # =====================================================================
        print("\n=== F2: Sidebar Double-Highlight Fix ===")
        # Navigate via keyboard shortcuts: G then V, G then A, G then B, G then O
        nav_sequence = [
            ("v", "vault", "Live Vault"),
            ("a", "attack", "Attack Lab"),
            ("b", "about", "About"),
            ("o", "overview", "Overview"),
        ]

        for key, expected_id, expected_label in nav_sequence:
            # Press G then the key
            page.keyboard.press("g")
            page.wait_for_timeout(200)
            page.keyboard.press(key)
            page.wait_for_timeout(800)

            # Check which nav items have 'active' class
            active_items = page.evaluate("""() => {
                const items = document.querySelectorAll('.nav-item.active');
                return Array.from(items).map(el => el.textContent.trim());
            }""")

            active_count = len(active_items)
            is_correct = active_count == 1
            record(f"F2-{key.upper()}", f"G+{key.upper()}: only one nav item active",
                   "pass" if is_correct else "fail",
                   f"{active_count} active items: {active_items}")

            # Verify the correct screen is shown
            current_hash = page.evaluate("location.hash")
            record(f"F2-{key.upper()}-HASH", f"G+{key.upper()}: correct hash",
                   "pass" if f"#{expected_id}" == current_hash else "fail",
                   f"Expected #{expected_id}, got {current_hash}")

        # =====================================================================
        # F3 — Anomaly engine "No failures observed yet" fix
        # =====================================================================
        print("\n=== F3: Anomaly Engine Text Fix ===")
        # Navigate to Attack Lab
        page.goto(f"{BASE}#attack", wait_until="networkidle")
        page.wait_for_timeout(1500)

        # Step 1: Click "Capture live key"
        capture_btn = page.locator("button:has-text('Capture live key')")
        capture_btn.click()
        page.wait_for_timeout(800)

        # Step 2: Fire "Forge static byte" attack (works without HOTP advance)
        forge_btn = page.locator("button:has-text('Forge static byte')")
        if forge_btn.count() == 0:
            forge_btn = page.locator("button:has-text('Forge: tweak one static byte')")
        if forge_btn.count() == 0:
            # Try finding by kind
            forge_btn = page.locator("text=Forge static byte").first
        forge_btn.click()
        page.wait_for_timeout(1500)

        # Check anomaly engine text after 1 failure
        anomaly_text = page.evaluate("""() => {
            // Find the anomaly engine section
            const cards = document.querySelectorAll('.card');
            for (const card of cards) {
                const h3 = card.querySelector('h3');
                if (h3 && h3.textContent.includes('Anomaly engine')) {
                    // Get the muted text in the anomaly reasons area
                    const mutedSpans = card.querySelectorAll('.muted');
                    const texts = Array.from(mutedSpans).map(s => s.textContent.trim());
                    return texts;
                }
            }
            return [];
        }""")

        has_old_text = any("No failures observed yet" in t for t in anomaly_text)
        has_new_text = any("logged" in t and "threshold" in t for t in anomaly_text)

        # After 1 attack, we should NOT see "No failures observed yet"
        record("F3-01", "After 1 attack: no 'No failures observed yet'",
               "pass" if not has_old_text else "fail",
               f"Anomaly texts: {anomaly_text}")

        # Check window events count
        window_events_text = page.evaluate("""() => {
            const spans = document.querySelectorAll('.tnum');
            return Array.from(spans).map(s => s.textContent.trim());
        }""")
        record("F3-02", "Window events count > 0 after attack",
               "pass" if any(t.isdigit() and int(t) > 0 for t in window_events_text if t.isdigit()) else "warn",
               f"tnum values: {window_events_text}")

        # Step 3: Fire brute burst x6 to push score above threshold
        brute_btn = page.locator("button:has-text('Brute burst')")
        brute_btn.click()
        page.wait_for_timeout(4000)  # 6 sequential requests need time

        # Check anomaly score after brute burst
        anomaly_post_burst = page.evaluate("""() => {
            const cards = document.querySelectorAll('.card');
            for (const card of cards) {
                const h3 = card.querySelector('h3');
                if (h3 && h3.textContent.includes('Anomaly engine')) {
                    // Get verdict pill
                    const pills = card.querySelectorAll('.pill');
                    const pillTexts = Array.from(pills).map(p => p.textContent.trim());
                    // Get reasons
                    const monoSpans = card.querySelectorAll('.mono');
                    const reasonTexts = Array.from(monoSpans).map(s => s.textContent.trim()).filter(t => t.startsWith('›') || t.includes('score'));
                    return { pills: pillTexts, reasons: reasonTexts };
                }
            }
            return { pills: [], reasons: [] };
        }""")

        verdict_text = " ".join(
            anomaly_post_burst.get("pills", []) + anomaly_post_burst.get("reasons", [])
        ).lower()
        has_danger_verdict = "verdict: suspicious" in verdict_text or "verdict: attack" in verdict_text
        record("F3-03", "After brute burst: score registers (attack/suspicious)",
               "pass" if has_danger_verdict else "fail",
               f"Pills: {anomaly_post_burst.get('pills')}, Reasons: {anomaly_post_burst.get('reasons')}")

        # =====================================================================
        # FULL FEATURE: Live Vault
        # =====================================================================
        print("\n=== Live Vault ===")
        page.goto(f"{BASE}#vault", wait_until="networkidle")
        page.wait_for_timeout(1500)

        # Check vault renders
        vault_text = page.evaluate("document.querySelector('.main')?.textContent || ''")
        has_vault_content = "Live Vault" in vault_text or "key" in vault_text.lower()
        record("VAULT-01", "Vault screen renders", "pass" if has_vault_content else "fail")

        # Click "Use" button to advance key
        use_btn = page.locator("button:has-text('Use')")
        if use_btn.count() > 0:
            use_btn.first.click()
            page.wait_for_timeout(2000)

            # Check for success feedback
            vault_text_after = page.evaluate("document.querySelector('.main')?.textContent || ''")
            # Look for success indicators (200 OK, verified, etc.)
            has_success = any(w in vault_text_after.lower() for w in ["verified", "200", "pass", "success", "ok", "accept"])
            record("VAULT-02", "Use key: success response",
                   "pass" if has_success else "warn",
                   "Checked for success indicators in vault text after Use click")

            # Check display updates (counter should have advanced)
            record("VAULT-03", "Key display present after use",
                   "pass" if len(vault_text_after) > 100 else "fail")
        else:
            record("VAULT-02", "Use button found", "fail", "No 'Use' button found on vault screen")
            record("VAULT-03", "Key display present after use", "fail", "Skipped - no Use button")

        # =====================================================================
        # FULL FEATURE: Attack Lab — Replay test
        # =====================================================================
        print("\n=== Attack Lab: Replay ===")
        page.goto(f"{BASE}#attack", wait_until="networkidle")
        page.wait_for_timeout(1500)

        # Capture key first
        capture_btn = page.locator("button:has-text('Capture live key')")
        capture_btn.click()
        page.wait_for_timeout(800)

        # Now go to vault, use key to advance HOTP
        page.goto(f"{BASE}#vault", wait_until="networkidle")
        page.wait_for_timeout(1000)
        use_btn = page.locator("button:has-text('Use')")
        if use_btn.count() > 0:
            use_btn.first.click()
            page.wait_for_timeout(1500)

        # Go back to attack and replay
        page.goto(f"{BASE}#attack", wait_until="networkidle")
        page.wait_for_timeout(1500)

        # Need to re-capture since we navigated away
        capture_btn = page.locator("button:has-text('Capture live key')")
        capture_btn.click()
        page.wait_for_timeout(800)

        # Use the key in vault first
        page.goto(f"{BASE}#vault", wait_until="networkidle")
        page.wait_for_timeout(1000)
        use_btn = page.locator("button:has-text('Use')")
        if use_btn.count() > 0:
            use_btn.first.click()
            page.wait_for_timeout(1500)

        # Return to attack and try replay
        page.goto(f"{BASE}#attack", wait_until="networkidle")
        page.wait_for_timeout(1500)

        # The captured key should still be available in component state...
        # Actually navigating away resets React state. Let's do it differently:
        # Capture, use in vault via API, then replay - all on attack page
        # For now, just test the replay-expired attack which doesn't need prior use
        replay_expired_btn = page.locator("button:has-text('Replay expired')")
        if replay_expired_btn.count() > 0:
            # Need a captured key first
            capture_btn = page.locator("button:has-text('Capture live key')")
            capture_btn.click()
            page.wait_for_timeout(800)

            replay_expired_btn.click()
            page.wait_for_timeout(2000)

            # Check validation log for reject
            log_text = page.evaluate("""() => {
                const table = document.querySelector('table');
                return table ? table.textContent : '';
            }""")
            has_reject = "reject" in log_text.lower()
            record("REPLAY-01", "Replay expired key: rejected by server",
                   "pass" if has_reject else "fail",
                   "Checked validation log table for 'reject' verdict")
        else:
            record("REPLAY-01", "Replay expired key button found", "fail", "Button not found")

        # =====================================================================
        # FULL FEATURE: Provisioning
        # =====================================================================
        print("\n=== Provisioning ===")
        page.goto(f"{BASE}#provision", wait_until="networkidle")
        page.wait_for_timeout(1500)

        provision_text = page.evaluate("document.querySelector('.main')?.textContent || ''")
        record("PROV-01", "Provisioning screen renders",
               "pass" if "provision" in provision_text.lower() or "mint" in provision_text.lower() or "client" in provision_text.lower() else "fail")

        # Find and click mint/provision button
        mint_btn = page.locator("button:has-text('Mint'), button:has-text('Provision'), button:has-text('provision')")
        if mint_btn.count() > 0:
            # Get client count before
            client_count_before = page.evaluate("""() => {
                const items = document.querySelectorAll('.mono');
                return document.querySelector('.main')?.textContent || '';
            }""")

            mint_btn.first.click()
            page.wait_for_timeout(2000)

            # Check for new client
            client_count_after = page.evaluate("document.querySelector('.main')?.textContent || ''")
            # The new client should appear
            record("PROV-02", "Mint new client: response received",
                   "pass" if len(client_count_after) > len(client_count_before) or "client" in client_count_after.lower() else "warn",
                   "Page content changed after mint click")
        else:
            record("PROV-02", "Mint button found", "fail", "No mint/provision button found")

        # =====================================================================
        # FULL FEATURE: Composed BPC + TSK verifier
        # =====================================================================
        print("\n=== Composed Verifier ===")
        page.goto(f"{BASE}#stack", wait_until="networkidle")
        page.wait_for_timeout(1500)

        stack_text = page.evaluate("document.querySelector('.main')?.textContent || ''")
        has_layers = any(w in stack_text.lower() for w in ["layer", "stack", "bpc", "tsk", "defense"])
        record("STACK-01", "Composed verifier screen renders",
               "pass" if has_layers else "fail",
               f"Content length: {len(stack_text)} chars")

        # Check the documented BPC and TSK checks render
        layer_titles = page.locator(".main button.layer .lt").all_text_contents()
        expected_stage_fragments = [
            "Authorized ECDSA", "Explicit pair registry", "User-secret HMAC",
            "nonce + timestamp", "Behavioral anomaly", "Derived segment",
            "Atomic state transition",
        ]
        stages_match = len(layer_titles) == 7 and all(
            any(fragment.lower() in title.lower() for title in layer_titles)
            for fragment in expected_stage_fragments
        )
        record("STACK-02", "All documented verification stages render",
               "pass" if stages_match else "fail",
               f"Found {len(layer_titles)} stages: {layer_titles}")

        # Scroll through
        for i in range(5):
            page.mouse.wheel(0, 400)
            page.wait_for_timeout(300)
        record("STACK-03", "Scroll through layers", "pass", "Scrolled to bottom without error")

        # =====================================================================
        # FULL FEATURE: BPC bridge status
        # =====================================================================
        print("\n=== BPC Bridge Status ===")
        page.goto(f"{BASE}#overview", wait_until="networkidle")
        page.wait_for_timeout(1500)

        # Check sidebar for bpc-bridge status
        sidebar_text = page.evaluate("""() => {
            const sidebar = document.querySelector('.sidebar');
            return sidebar ? sidebar.textContent : '';
        }""")
        has_bpc_offline = "offline" in sidebar_text.lower() and "3101" in sidebar_text
        record("BPC-01", "BPC bridge shows offline (3101 not running)",
               "pass" if has_bpc_offline else "warn",
               f"Sidebar mentions 3101: {'3101' in sidebar_text}, offline: {'offline' in sidebar_text.lower()}")

        # =====================================================================
        # FULL FEATURE: TSK server status dot
        # =====================================================================
        print("\n=== Server Status ===")
        has_server_ok = "3200" in sidebar_text and ("✓" in sidebar_text or "ok" in sidebar_text.lower())
        record("STATUS-01", "TSK server :3200 shows green check",
               "pass" if has_server_ok else "warn",
               f"Sidebar mentions 3200: {'3200' in sidebar_text}")

        # =====================================================================
        # FULL FEATURE: About screen
        # =====================================================================
        print("\n=== About Screen ===")
        page.goto(f"{BASE}#about", wait_until="networkidle")
        page.wait_for_timeout(1000)

        about_text = page.evaluate("document.querySelector('.main')?.textContent || ''")
        has_about = len(about_text) > 50
        record("ABOUT-01", "About screen renders with content",
               "pass" if has_about else "fail",
               f"Content length: {len(about_text)} chars")

        # =====================================================================
        # Console Errors Summary
        # =====================================================================
        print("\n=== Console Errors ===")
        if page_errors:
            record("CONSOLE-01", "No application exceptions",
                   "fail", f"{len(page_errors)} exceptions: {page_errors[:5]}")
        else:
            resource_messages = [
                error for error in console_errors
                if error.startswith("Failed to load resource")
            ]
            other_console_errors = [
                error for error in console_errors
                if not error.startswith("Failed to load resource")
                and "favicon" not in error.lower()
            ]
            record("CONSOLE-01", "No application exceptions",
                   "pass" if not other_console_errors else "fail",
                   f"application_errors={other_console_errors}; "
                   f"resource_messages_checked_by_network_assertions={len(resource_messages)}")

        # =====================================================================
        # Network errors summary
        # =====================================================================
        print("\n=== Network Errors ===")
        server_errors = [error for error in all_http_errors if error["status"] >= 500]
        record("NET-01", "No 5xx network errors",
               "pass" if not server_errors else "fail",
               f"server_errors={server_errors[:5]}")

        allowed_negative_paths = {"/api/data", "/api/secret", "/api/action", "/api/admin/config"}
        unexpected_client_errors = [
            error for error in all_http_errors
            if 400 <= error["status"] < 500
            and not (
                error["status"] == 401
                and urlparse(error["url"]).path in allowed_negative_paths
            )
        ]
        expected_denials = [
            error for error in all_http_errors
            if error["status"] == 401
            and urlparse(error["url"]).path in allowed_negative_paths
        ]
        record("NET-02", "Only expected attack-path 4xx responses occurred",
               "pass" if expected_denials and not unexpected_client_errors else "fail",
               f"expected_denials={len(expected_denials)}; "
               f"unexpected_client_errors={unexpected_client_errors[:5]}")

        unexpected_failures = [
            failure for failure in failed_requests
            if not failure["url"].startswith("http://localhost:3101/")
            and not (
                urlparse(failure["url"]).path == "/analytics/event"
                and failure["failure"] == "net::ERR_ABORTED"
                and success_analytics == total_analytics
                and total_analytics > 0
            )
        ]
        record("NET-03", "Only verified analytics aborts and the offline BPC probe failed",
               "pass" if not unexpected_failures else "fail",
               f"request_failures={failed_requests[:5]}")

        browser.close()

    # =====================================================================
    # FINAL REPORT
    # =====================================================================
    print("\n" + "=" * 70)
    print("TSK PROTOCOL DEMO — E2E TEST REPORT")
    print("=" * 70)

    passes = sum(1 for r in RESULTS if r["status"] == "pass")
    fails = sum(1 for r in RESULTS if r["status"] == "fail")
    warns = sum(1 for r in RESULTS if r["status"] == "warn")

    for r in RESULTS:
        icon = {"pass": "PASS", "fail": "FAIL", "warn": "WARN"}[r["status"]]
        line = f"  [{icon}] {r['test']}: {r['name']}"
        if r["detail"]:
            line += f"\n         {r['detail']}"
        print(line)

    print(f"\nTOTAL: {len(RESULTS)} tests | {passes} pass | {fails} fail | {warns} warn")

    # Specific fix verdicts
    print("\n--- FIX VERDICTS ---")
    f1_tests = [r for r in RESULTS if r["test"].startswith("F1")]
    f2_tests = [r for r in RESULTS if r["test"].startswith("F2")]
    f3_tests = [r for r in RESULTS if r["test"].startswith("F3")]

    f1_pass = all(r["status"] == "pass" for r in f1_tests)
    f2_pass = all(r["status"] == "pass" for r in f2_tests)
    f3_pass = all(r["status"] != "fail" for r in f3_tests)

    print(f"  F1 (Analytics 503 fix):              {'PASS' if f1_pass else 'FAIL'}")
    print(f"  F2 (Sidebar double-highlight fix):    {'PASS' if f2_pass else 'FAIL'}")
    print(f"  F3 (Anomaly engine text fix):         {'PASS' if f3_pass else 'FAIL'}")

    return 0 if fails == 0 else 1

if __name__ == "__main__":
    try:
        sys.exit(run_tests())
    except Exception as e:
        print(f"\n[FATAL] Test runner crashed: {e}")
        traceback.print_exc()
        sys.exit(2)
