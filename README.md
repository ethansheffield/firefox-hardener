<div align="center">

**Firefox Hardener v2.6.0**  
A cross-platform Python script to automatically secure and harden Mozilla Firefox for maximum privacy using official Enterprise Policies.

</div>

---

## About The Project

Default browser settings often prioritize features over user privacy. While Firefox is a great browser, it requires significant manual configuration to disable telemetry, lock down privacy settings, and install the right extensions.

This script automates the entire process. Unlike older methods that use `user.js` (which can be overridden or fail to apply settings correctly), this tool uses Mozilla's **Enterprise Policy engine**. This creates a locked, administrator-enforced configuration that is robust, reliable, and cannot be accidentally changed by the user.

The result is a browser that is hardened and ready for private, secure use immediately after running the script.

---

## Key Features

- **Cross-Platform:** Works on Windows, macOS, and Linux.
- **Automated Setup:**
  - Detects if Firefox is installed.
  - Offers to automatically install Firefox if it's missing (via `apt`, `dnf`, `pacman`, `brew`, etc.).
- **Robust Policy-Based Hardening:**
  - Sets DuckDuckGo as the locked, non-changeable default search engine.
  - Disables all telemetry (analytics, studies, pings, data collection).
  - Enforces privacy (enables Global Privacy Control, disables Pocket).
  - Disables the built-in password manager and autofill.
- **Managed Privacy Extensions (force-installed):**
  - uBlock Origin  
  - Multi-Account Containers  
  - Temporary Containers  
  - LocalCDN  
  - ClearURLs  
  - CanvasBlocker  
- **Blocks other add-ons:** Prevents any unapproved extensions from being installed.
- **Safe and User-Focused:**
  - Prompts for backup before major changes.
  - Requires explicit confirmation before destructive actions.
- **Reversible:** Can remove all applied policies and restore Firefox defaults.

---

## How to Use

> **Important:** This script modifies the Firefox installation directory (e.g., `C:\Program Files\Mozilla Firefox` or `/usr/lib/firefox`). It must be run with elevated privileges.

### Step 1: Download the Script

Download `hardener.py` to a known location on your computer.

### Step 2: Run with Administrator/Sudo Privileges

<details>
<summary><strong>Click for macOS & Linux Instructions</strong></summary>

1. Open your **Terminal**.  
2. Navigate to the directory where you saved the script:  

```bash
cd /path/to/your/script

	3.	Run the script using sudo:

sudo python3 hardener.py

</details>


<details>
<summary><strong>Click for Windows Instructions</strong></summary>


	1.	Right-click the Start Menu and select PowerShell (Admin) or Terminal (Admin).
	2.	Navigate to the directory where you saved the script:

cd C:\path\to\your\script

	3.	Run the script:

python hardener.py

</details>


Step 3: Follow the Menu

Use the interactive menu to apply, manage, or remove hardening settings.

⸻

Menu Options

Installation
	•	1. Quick Install - Balanced: Applies core privacy policies and a recommended set of extensions.
	•	2. Quick Install - Maximum Security: Applies core policies and all available extensions.
	•	3. Custom Install: Choose which extensions to install alongside core policies.

Maintenance & Recovery
	•	4. Remove All Policies: Deletes policies.json, restoring Firefox defaults.
	•	5. Backup Firefox Profile: Creates a .zip backup of bookmarks, history, etc.
	•	6. Restore Firefox Profile: Restores from a backup (destructive, overwrites profile).
	•	7. Verify Hardening Status: Checks if a policy file is active.
	•	8. Install/Update Firefox: Attempts installation/update via package manager.

Application
	•	9. Exit: Closes the program.

⸻

Safety and Backups
	•	Applying Hardening (Options 1, 2, 3): Non-destructive to your personal data (bookmarks, passwords, history), but will disable any existing extensions not on the approved list. Removing policies (Option 4) will re-enable them.
	•	Backup (Option 5): A 100% safe operation that simply creates a copy of your profile.
	•	Restore (Option 6): A destructive operation that replaces your current profile with a backup. The script requires explicit yes confirmation before proceeding.

Best Practice: Always use Option 5 (Backup) before applying policies for the first time or restoring from an old backup.

⸻

Disclaimer

This script is provided as-is without warranty. It modifies system files in the Firefox installation directory and manages user profile data. Always back up important data before running. Use at your own risk.

⸻

License

Distributed under the MIT License. See LICENSE for details.

Copyright (c) 2025

