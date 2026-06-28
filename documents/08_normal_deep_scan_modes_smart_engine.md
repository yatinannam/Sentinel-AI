# Auto-Documentation: Normal & Deep Scan Modes with Smart Scan Engine

## Date
2026-06-28

## User Prompt
Enhance the AI-Powered Endpoint Security Platform by implementing two distinct scanning modes: Normal Scan and Deep Scan. The objective is to provide users with a fast daily scan for commonly targeted areas and a comprehensive scan for complete system security.

## Changes Made
- **[NEW]** [scanService.ts](file:///d:/The%20Proj/SentinelAI/electron/services/scanService.ts) - The advanced scanner orchestrator implementing Quick/Deep/Custom scan routing, trusted publisher signature skips via PowerShell commands, SHA-256 hash caching, worker concurrency limits, duration tracking, and dynamic ETA estimation.
- **[MODIFY]** [database.ts](file:///d:/The%20Proj/SentinelAI/electron/services/database.ts) - Initialized SQLite tables `scans` (date, type, duration, scan metrics, security score, threat reports details) and `file_cache` (sha256, path, mtime, lastStatus). Exposed `getScans()`, `addScan()`, `getFileCache()`, and `setFileCache()` methods.
- **[MODIFY]** [preload.ts](file:///d:/The%20Proj/SentinelAI/electron/preload.ts) - Bridged EDR scanner APIs `runNormalScan()`, `runDeepScan()`, `getScanHistory()`, and the `onScanReportCompleted()` listener.
- **[MODIFY]** [main.ts](file:///d:/The%20Proj/SentinelAI/electron/main.ts) - Bootstrap `scanService` setWindow hooks, connected the IPC handles for scan pause/resume/cancel controls, and registered scanner execution handles.
- **[MODIFY]** [App.tsx](file:///d:/The%20Proj/SentinelAI/renderer/src/App.tsx) - Designed the React Scan Center layout, supporting Quick Scan, Deep Scan, and Custom Scan configs, real-time progress metering, interactive diagnostic reports detail with AI vertical checkpoint gates visualization, and full historical reports log.

## Rationale / Design Decisions
1. **Scope Division**:
   - **Quick (Normal) Scan**: Targets common injection folders (`Desktop`, `Documents`, `Downloads`, `Startup Programs`, `Running Processes`, `Active Services`, `Startup Registry Keys`, `Recent Downloads`, `USB Drives`). Applies YARA, Static AI, and basic Threat Intel lookups. Runs fast, avoiding system disruption.
   - **Deep Scan**: Scans all folders, libraries, hidden directories, browser extensions, boot configurations, and memory processes. Runs full multi-layer detection pipelines.
2. **Performance Improvements**:
   - **SHA-256 Cache Check**: Compares local file modification times (`mtime`) against `file_cache` rows. If they match, skips deep AI scans and registers previous verdict.
   - **Authenticode Trusted Publisher Verification**: Executed PowerShell command `Get-AuthenticodeSignature` on Windows system directories. Skipped files signed by `Microsoft`, `Windows`, or `Intel` to prevent duplicate scanning.
   - **Concurrency Limit**: Standardized worker queues to execute 4 subprocesses concurrently, preventing resource exhaustion during heavy file scans.
3. **Double Column Results View**:
   - Integrated the layered diagnostics detail (`renderAiLayerAnalysis()`) directly into the results panel of the Scan Center so users can check individual security checkpoint gates for any flagged threat in the report.

## Verification / Testing
- Verified successful compilation via `npm run build`.
- Monitored process workers count, signature skip logs, and SQLite database commits using visual tracing.
