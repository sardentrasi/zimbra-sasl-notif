# Zimbra SASL Security & Auto-Lock Script

A robust, modular Bash-based security tool designed for **Zimbra Collaboration Suite**. This script analyzes `zimbra.log` to detect brute-force attacks and automatically mitigates compromised accounts by locking them when suspicious successful logins occur from foreign IP addresses.

## 🚀 Features

This tool operates using a tiered logic system to minimize false positives while ensuring account security:

### 1. Volume Attack Detection (Module 1)
* **Function:** Identifies the top 40 IP addresses performing high-volume brute-force attacks.
* **Action:** Logs the detection to the console and generates a GeoIP report.
* **Status:** *Passive (Monitoring only).*

### 2. Distributed Attack Detection (Module 2)
* **Function:** Identifies accounts being targeted by multiple distinct IP addresses simultaneously (distributed brute-force).
* **Action:** Logs the detection to the console.
* **Status:** *Passive (Monitoring only).*

### 3. Compromise Detection & Auto-Lock (Module 3)
* **Function:** The "Kill Switch". It cross-references accounts currently under attack (from Module 1) with successful login logs.
* **Logic:** If an account is listed as "Under Attack" **AND** successfully logs in from a **Non-Indonesian (Foreign) IP**, the script assumes the password has been breached.
* **Action:**
    1.  **Locks the account immediately** (`zmprov ma ... locked`).
    2.  **Sends an alert email** to the IT Admin.
    3.  **Records the event** to prevent re-locking the same session repeatedly.
* **Status:** *Active (Enforcement).*

## 📋 Prerequisites

* **OS:** Linux (tested on CentOS/RHEL/Ubuntu based Zimbra servers).
* **Zimbra:** Installed and running (specifically utilizing Postfix/SASL logs).
* **Dependencies:**
    * `geoip-bin` (or `geoip-database` with `geoiplookup` command).
    * Standard tools: `awk`, `sed`, `grep`, `sort`, `uniq`.
    * `sendmail` (provided by Zimbra).

## 🛠️ Installation

1.  **Prepare the Directory**
    ```bash
    mkdir -p /opt/scripts/saslnotif
    cd /opt/scripts/saslnotif
    ```

2.  **Install Scripts**
    * Create `sasl_combined.sh` and paste the main script content.
    * Create `agent.sh` and paste the runner content.

3.  **Set Permissions**
    Make the scripts executable:
    ```bash
    chmod +x /opt/scripts/saslnotif/sasl_combined.sh
    chmod +x /opt/scripts/saslnotif/agent.sh
    ```

4.  **Create Whitelist (Optional)**
    Create a file to exclude specific accounts (e.g., admins, service accounts) from ever being locked.
    ```bash
    touch /opt/scripts/saslnotif/whitelist
    # Add emails one per line, e.g.:
    # admin@myhaldin.com
    # services@myhaldin.com
    ```

## ⚙️ Configuration

### 1. Main Script Settings
Open `sasl_combined.sh` to adjust thresholds:

```bash
# --- CONFIGURATION ---
warn_percentage_volume=5      # Min failures to flag volume attack
warn_percentage_multi_ip=5    # Min distinct IPs to flag distributed attack
basepath=/opt/scripts/saslnotif
```

> **Important:** Ensure your server's timezone and `date` command match the Zimbra log format.

## 🏃 Usage

### Manual Run (Testing)
You can run the core logic manually to check the current status of attacks:

```bash
./sasl_combined.sh
```

### Automatic Run (Daemon Mode)
Use the `agent.sh` wrapper to run the script continuously in the background.

1.  **Edit frequency (Optional):**
    Open `agent.sh` and adjust `sleep 30`.
    *Recommendation:* Increase to `sleep 300` (5 minutes) to reduce server load and log noise.

2.  **Start the Agent:**
    ```bash
    bash agent.sh
    ```
    Or configure it as a systemd service (recommended for production).

## 📂 File Structure
* **sasl_combined.sh:** The main logic script containing all 3 modules.
* **agent.sh:** A loop wrapper to execute the main script periodically.
* **whitelist:** List of email addresses excluded from locking.
* **geo_report.log:** Generated report showing IPs and Locations of attackers.
* **processed_success.log:** Database of handled compromise events to prevent loop-locking.
* **mktemp* & account_sasl_tmp:** Temporary files used during execution (auto-cleaned).

## ⚠️ Important Notes
1.  **GeoIP Database:** This script relies heavily on `geoiplookup`. Ensure your GeoIP database is up to date to avoid "IP Address not found" errors.
    ```bash
    # Example update command
    sudo geoipupdate
    ```
2.  **Log Rotation:** The script reads `/var/log/zimbra.log`. Ensure your log rotation settings are correct so this file doesn't become too large, or adjust the script to use `tail` if performance becomes an issue.

## 📝 License
This project is open-source. Feel free to modify it to suit your specific infrastructure needs.

---
*Disclaimer: This script interacts directly with Zimbra provisioning (`zmprov`). Use with caution and test in a staging environment first.*
