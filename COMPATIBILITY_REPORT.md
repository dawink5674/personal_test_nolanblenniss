# OS Compatibility Report for MWCCDC Liaison Ansible

## Summary
The codebase was audited and dry-run tested against mock environments to verify compatibility with the specific Operating Systems listed in your inventory: **Ubuntu 24.04**, **Fedora 42**, and **Oracle Linux 9.2**.

## Compatibility Verdict
**The script is largely compatible with the supported OSs, with minor caveats for Oracle Linux Minimal installs.**

### Detailed OS Support Analysis

| Role | Ubuntu 24.04 (Debian Family) | Fedora 42 (RedHat Family) | Oracle Linux 9.2 (RedHat Family) | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **docker_install** | ✅ Full Support | ✅ Full Support | ⚠️ Minor Risk | Uses `dnf config-manager`. Oracle Linux Minimal might require `dnf-plugins-core` first. |
| **firewall_hardening** | ✅ `iptables-persistent` | ✅ `iptables-services` | ✅ `iptables-services` | Correctly handles service names. |
| **xrdp_server** | ✅ `xrdp`, `xfce4` | ✅ `xrdp`, `xfce4-session` | ✅ `xrdp`, `xfce4-session` | Handles differing package names. |
| **rootkit_scanner** | ✅ Native packages | ✅ Native packages | ✅ via EPEL | Automatically installs `epel-release` on Oracle Linux. |
| **vpn_manager** | ✅ Native packages | ✅ Native packages | ✅ Native packages | WireGuard/OpenVPN are standard packages. |
| **clamav_antivirus** | ✅ `clamav-daemon` | ✅ `clamd` | ✅ `clamd` | Handles service name differences. |

## How the "Rest" of the Functions Work
During previous testing, only `system` and `tshark` roles were fully executed on localhost. Here is how the other key functions operate based on code analysis and dry runs:

1.  **Docker Installation & Services:**
    *   **Logic:** Detects package manager (`apt` vs `dnf`).
    *   **Ubuntu:** Adds Docker official GPG key and repo, installs via `apt`.
    *   **Fedora/Oracle:** Uses `dnf config-manager` to add the repo, installs via `dnf`.
    *   **Services:** Pulls images defined in `group_vars/all.yml` (e.g., OpenVPN, Cowrie) and runs them as containers.

2.  **Firewall Hardening:**
    *   **Logic:** Flushes existing rules (optional), sets default policy to DROP for Input/Forward, ACCEPT for Output.
    *   **Rules:** Explicitly allows SSH (port 22), loopback, and established connections.
    *   **Persistence:** Saves rules to `/etc/iptables/rules.v4` (Ubuntu) or `/etc/sysconfig/iptables` (RedHat) and ensures the appropriate service (`netfilter-persistent` vs `iptables`) is enabled.

3.  **Rootkit Scanner:**
    *   **Logic:** Installs `rkhunter` and `chkrootkit`.
    *   **Oracle Linux Specifics:** Detects it's not Fedora and installs `epel-release` first to access `chkrootkit`.
    *   **Operation:** Updates databases, runs scans, and schedules daily cron jobs.

4.  **VPN Manager (WireGuard):**
    *   **Logic:** Installs `wireguard-tools`.
    *   **Key Management:** Generates private/public keys on the server if missing.
    *   **Config:** Templates `/etc/wireguard/wg0.conf` using variables from `group_vars`.
    *   **Service:** Enables `wg-quick@wg0`.

## Recommendations for Oracle Linux
To ensure 100% reliability on a minimal Oracle Linux 9.2 install, consider manually running this command if the Docker installation fails:
```bash
sudo dnf install -y dnf-plugins-core
```
This ensures the `dnf config-manager` command used by the Docker role is available.
