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

