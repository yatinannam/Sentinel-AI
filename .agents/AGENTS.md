# Agent Instructions: Auto-Documentation of Code Changes and Prompts

You must automatically document every user prompt, technical discussion, and code change made during this pair programming session in the `documents/` folder.

## Rules for Documentation:
1. **Timing**: Create or update the documentation at the end of each user request / prompt where a change is made.
2. **File Location**: Documents must be saved in the `documents/` folder of the workspace.
3. **Format**: Follow the naming convention `XX_description_of_change.md`, incrementing the index number (e.g., `04_ffmpeg_dll_troubleshooting.md`, `05_new_feature_name.md`), or update the relevant existing change logs.
4. **Content**: Every document must contain:
   - **Date**: The current local date.
   - **User Prompt**: The user's prompt or request.
   - **Changes Made**: Detailed list of files modified, added, or deleted, including markdown file links using the `file://` scheme.
   - **Rationale / Design Decisions**: Explanation of why the change was made and the technical details.
   - **Verification / Testing**: How the change was tested or verified.
5. **Update README**: Always append the new document to the Table of Contents in [documents/README.md](file:///d:/The%20Proj/SentinelAI/documents/README.md).
