# SentinelAI Change Logs & Reference Documentation

Welcome to the SentinelAI reference documentation directory. This directory contains detailed logs of system releases, modifications, and core service changes.

> [!NOTE]
> This directory is added to `.gitignore` to keep documentation assets local and separate from git history.

## Table of Contents

1.  **[v1.0.0 Initial Setup](file:///d:/The%20Proj/SentinelAI/documents/01_initial_release_v1_0_0.md)**
    *   Overview of the EDR architecture.
    *   Description of file, network, process, registry, USB, and scanner services.
    *   Initial setup of Python AI model and Electron/React architecture.
2.  **[Dashboard Enhancements & Scan Controls](file:///d:/The%20Proj/SentinelAI/documents/02_dashboard_and_scan_controls.md)**
    *   Real-time system CPU & RAM utilization gauge panels.
    *   Scan pause, resume, and cancellation mechanics.
    *   UI design upgrades (hash formatting, truncation tooltips, etc.).
3.  **[SQLite Database Migration](file:///d:/The%20Proj/SentinelAI/documents/03_sqlite_database_migration.md)**
    *   Migration details from local JSON file persistence to transactional SQLite.
    *   Database tables, relationships, and settings indexing schemas.
    *   Dependency adjustments (`better-sqlite3`).
4.  **[ffmpeg.dll & tsconfig.json Troubleshooting](file:///d:/The%20Proj/SentinelAI/documents/04_ffmpeg_dll_and_tsconfig_troubleshooting.md)**
    *   Diagnosis of resource locking on `ffmpeg.dll` by the background system tray application.
    *   TypeScript module resolution target optimization.
5.  **[Auto-Documentation System](file:///d:/The%20Proj/SentinelAI/documents/05_auto_documentation_system.md)**
    *   Setup of project-scoped AI instructions in `.agents/AGENTS.md`.
    *   Automating the logging of user prompts and technical changes.
6.  **[Active Process Sync & WMIC Deprecations](file:///d:/The%20Proj/SentinelAI/documents/06_active_process_sync_wmic_deprecation.md)**
    *   Transition from deprecated `wmic` process monitoring to compressed PowerShell JSON queries.
    *   Implementation of self-query bypass rules to prevent process killing loops.
7.  **[Multi-Layer AI Threat Detection Engine](file:///d:/The%20Proj/SentinelAI/documents/07_multi_layer_ai_threat_detection_engine.md)**
    *   6-layer defense mechanism integrating signature detection, native PE features, numpy TensorFlow neural networks, VirusTotal threat intelligence lookup, weighted score decision, and automated containments.
    *   React visual dashboard widgets and expandable timelines.
8.  **[Normal & Deep Scan Modes & Smart Scan Engine](file:///d:/The%20Proj/SentinelAI/documents/08_normal_deep_scan_modes_smart_engine.md)**
    *   Dedicated Quick (Normal) Scan, Full System (Deep) Scan, and Custom scans.
    *   Trusted system file skip, SHA-256 caching database mechanism, worker concurrency limit, duration tracking, and dynamic ETA estimators.
    *   Scan Center React UI design and double column reports view.
9.  **[Production Desktop App Transition](file:///d:/The%20Proj/SentinelAI/documents/09_production_desktop_app_transition.md)**
    *   Dynamic BGR binary BMP system tray status indicator manager and minimize-to-tray mechanics.
    *   Automatic startup run-at-login boot settings registration and `--startup` args checks.
    *   4-step user onboarding initialization wizard overlay (Welcome -> Shields Config -> Quick Scan -> Activated checklist).
    *   Polished categorized settings groups (General, Shields, Scanning Engines, Alerts, Intel & Privacy) and single-click non-elevated NSIS installer configs.
