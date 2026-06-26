# Change Document: ffmpeg.dll and tsconfig.json Troubleshooting

**Date:** June 26, 2026  
**Status:** Completed  
**User Prompt:** "So i have this error coming and when i make a package it is showing me ffmpeg.dll error"

---

## 1. Context & Problem Statement

When attempting to package the Electron application via `npm run package` (which runs `electron-builder`), an error occurs related to `ffmpeg.dll` (usually an `EPERM` or `EBUSY` error indicating the file is locked or access is denied). Additionally, there is a visual warning in [electron/tsconfig.json](file:///d:/The%20Proj/SentinelAI/electron/tsconfig.json#L12) under `"moduleResolution": "node"`.

---

## 2. Rationale & Diagnosis

1. **`ffmpeg.dll` Locking Issue:**  
   The application features a system tray integration. When the user closes the dashboard window, the application process (`SentinelAI.exe`) continues running in the background. Because the active process loads `ffmpeg.dll` (Chromium's dependency for media support), Windows locks the DLL. When `electron-builder` runs subsequent builds, it attempts to overwrite `dist/win-unpacked/ffmpeg.dll`, which fails due to this lock.
   
2. **TypeScript Warning:**  
   `"moduleResolution": "node"` triggers compiler/IDE warnings in newer environments suggesting migration to modern, explicit options like `node10` or `node16`.

---

## 3. Recommended Actions & Fixes

* **Background Process Termination:**  
  Quit any active background instances of SentinelAI from the system tray (Right-click -> Quit SentinelAI) or kill `SentinelAI.exe` tasks using the Task Manager before running package commands.
  
* **Exclude Project Directory from Antivirus Scanning:**  
  Add `d:\The Proj\SentinelAI` to the antivirus exemption list to prevent security tools from locking `ffmpeg.dll` during compilation or file copying.

* **TypeScript Resolution Target:**  
  Update `moduleResolution` to `"node10"` inside [electron/tsconfig.json](file:///d:/The%20Proj/SentinelAI/electron/tsconfig.json) to resolve the IDE warning.

---

## 4. Verification

* Verified that a clean run of `npm run package` completes successfully when no background instance of `SentinelAI.exe` is holding a lock on the DLL.
