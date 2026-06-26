# Change Document: Dashboard Enhancements & Scan Controls

**Date:** June 26, 2026  
**Commit Hash:** `5110565d1d509f8e14b2894abcd5bcc06fa8aef8`  
**Description:** Expanded the capabilities of the React renderer and Electron background runner to display real-time host resource statistics and support interactive scanning controls.

---

## 1. System Resource Monitoring

We introduced real-time hardware status metrics on the client dashboard to track device performance during security operations:

*   **CPU Telemetry:** Implemented delta calculations based on CPU times (`user`, `nice`, `sys`, `idle`, `irq`) via `os.cpus()`. This measures active usage percentages rather than cumulative history.
*   **RAM Telemetry:** Computed memory allocation using `os.totalmem()` and `os.freemem()`.
*   **System Specifications:** Created IPC bridges (`get-system-specs`) to return host CPU model strings, OS name/release type (e.g., Windows 10/11, macOS, Linux), architecture, and hostname.
*   **UI Gauge Widgets:** Built stylized dashboard panels showing colored status indicators for CPU and memory usage, complete with specific CPU specifications on hover.

---

## 2. Scan Execution Controls

To give users more direct command over security tasks, the static scanner was replaced with a controllable, async execution workflow:

*   **State Machine:** Integrated `isScanPaused`, `isScanCancelled`, and `isScanRunning` control states inside the Electron main process scanner loop.
*   **Pause and Resume:**
    *   The file queue checking logic evaluates a `checkPause()` handler inside its loop.
    *   When paused, the process delays execution using an async timer loop while keeping the scanner in a waiting state.
    *   The UI displays a yellow amber theme indication with "RESUME SCAN" and "STOP SCAN" commands.
*   **Stop Scan:**
    *   Canceling the scan immediately flags `isScanCancelled` to true.
    *   The scanning queue terminates and resets the dashboard state to "System Idle".
*   **Dismiss Action:** Users can dismiss completed scans via a "Dismiss" action button, resetting the panel to the idle state.

---

## 3. Threat Log UI & Usability Upgrades

Enhanced readability of incident and threat tables to accommodate long hash keys and path names:

*   **Hash Slicing:** Modified the SHA256 hashes to show `XXXXXX...XXXXXX` (first/last 8 characters) with full hash tooltips on hover to prevent layout overflow.
*   **Path Clamping:** Wrapped original paths in truncated wrappers to prevent layout stretching.
*   **Detail Clamp:** Clamped long detail responses to 2 lines, using tooltip displays for full messages.
