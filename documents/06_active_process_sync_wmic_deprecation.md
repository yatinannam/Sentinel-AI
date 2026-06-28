# Change Log: 06 - Active Process Sync & WMIC Deprecations

**Date**: June 28, 2026

## User Prompt
The active processes dashboard always shows the same applications and does not sync with the applications currently open on the system.

## Changes Made
- Modified [electron/services/processMonitor.ts](file:///d:/The%20Proj/SentinelAI/electron/services/processMonitor.ts):
  - Changed the process query command from deprecated `wmic` to a fast, compressed JSON-format PowerShell `Get-CimInstance Win32_Process` query.
  - Replaced CSV parsing logic with clean JSON parsing using `parsePowerShellOutput`.
  - Added an exclusion rule to prevent the application from flagging its own process telemetry PowerShell command as a suspicious process.

## Rationale & Design Decisions
- **WMIC Deprecation**: Modern Windows 11 systems no longer package the `wmic` utility by default, causing the application to fail the query execution and fall back on static mock data. Replacing it with standard PowerShell ensures compatibility.
- **Performance Optimization**: Spawning console output for hundreds of processes creates huge overhead due to terminal rendering. Compressing the output to JSON (`ConvertTo-Json -Compress`) and setting a maximum buffer size avoids bottlenecking the system and parses reliably.
- **Suspicious Process Bypass**: The system flags PowerShell processes running with execution bypasses or hidden window styles. Since our monitoring command runs with `-WindowStyle Hidden`, it would self-flag and attempt to kill itself. Adding an explicit bypass for the telemetry query pattern solves this feedback loop.

## Verification & Testing
- Ran type compilation successfully (`npm run build:electron`).
- Started dev environment (`npm run dev`) and validated that the application retrieves processes correctly and does not experience self-sabotage/killing behavior.
