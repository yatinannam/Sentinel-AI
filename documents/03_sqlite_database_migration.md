# Change Document: SQLite Database Migration

**Date:** June 26, 2026  
**Status:** In Progress (Working Tree / Staged Changes)  
**Description:** Migrated database backend from in-memory JSON file serialization to a structured SQLite database using `better-sqlite3` to ensure data integrity, faster queries, and proper transaction handling.

---

## 1. Context and Problem Statement

Initially, SentinelAI used an in-memory object structure saved to a JSON file via `fs.writeFileSync()` on every database update. This simple JSON model suffered from several limitations:
*   **Race Conditions:** Multiple background services trying to update logs simultaneously could overwrite each other's data.
*   **Performance Overhead:** Writing the entire JSON array of threat logs to disk repeatedly degrades I/O performance as incident logs grow.
*   **Data Corruption Risk:** If the application crashes during a write operation, the configuration file could be corrupted.

---

## 2. Solution: SQLite with `better-sqlite3`

We integrated `better-sqlite3` to implement a relational, disk-backed storage engine.

### Schema Design

The SQLite database establishes three tables:

1.  **`settings` Table:**
    *   Columns: `id (PRIMARY KEY)`, `aiSensitivity (INTEGER)`, `realTimeProtection (INTEGER/BOOLEAN)`, `networkProtection (INTEGER/BOOLEAN)`, `autoQuarantine (INTEGER/BOOLEAN)`, `notifications (INTEGER/BOOLEAN)`, `startWithWindows (INTEGER/BOOLEAN)`, `virusTotalApiKey (TEXT)`.
    *   Default settings row auto-populates upon database creation if not already present.

2.  **`incidents` Table:**
    *   Columns: `id (PRIMARY KEY)`, `name (TEXT)`, `path (TEXT)`, `hash (TEXT)`, `type (TEXT)`, `severity (TEXT)`, `confidence (INTEGER)`, `time (TEXT)`, `status (TEXT)`, `actionTaken (TEXT)`, `details (TEXT)`.
    *   An index `idx_incidents_time` is created on the `time DESC` column to optimize the retrieval speed of dashboard logs.

3.  **`quarantine` Table:**
    *   Columns: `id (PRIMARY KEY)`, `originalPath (TEXT)`, `quarantinePath (TEXT)`, `hash (TEXT)`, `size (INTEGER)`, `date (TEXT)`.

---

## 3. Implementation Details (`database.ts`)

*   **Initialization:** The `DatabaseService` constructor resolves the user data path, verifies directory existence, opens the SQLite file, and runs a series of schema initialization `CREATE TABLE IF NOT EXISTS` commands inside a `try-catch` block.
*   **Data Operations:**
    *   **Retrievals:** Use compiled statements (e.g., `SELECT * FROM incidents ORDER BY time DESC`) returning strongly-typed records.
    *   **Inserts/Updates:** Replaced mutating arrays with parameterized inserts, preventing SQL injection issues (e.g., `INSERT INTO incidents ... VALUES (?, ?, ?, ...)`).
    *   **Settings Updates:** Generates dynamic UPDATE clauses based on settings key modification parameters to limit writes to altered configurations.

---

## 4. Dependencies Updated

*   **`package.json`:**
    *   Added `"better-sqlite3": "^12.11.1"` to runtime `dependencies`.
    *   Added `"@types/better-sqlite3": "^7.6.13"` to development `devDependencies`.
