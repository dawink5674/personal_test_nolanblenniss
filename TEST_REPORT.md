# Test Report for MWCCDC Liaison Ansible

## Summary
The codebase was tested using syntax checks, linting, and dry-run execution against localhost. Several issues were identified, ranging from structural problems to linting violations.

## critical Findings

### 1. `group_vars` and `host_vars` Loading Issue
**Severity:** High
**Description:** When running playbooks from the `playbooks/` directory (as recommended in README), Ansible does not load variables from `group_vars/` and `host_vars/` located in the repository root. This causes playbooks to fail with "undefined variable" errors (e.g., `docker_services`).
**Reproduction:**
```bash
ansible-playbook playbooks/liaison_main.yml --check -e tool=all -l localhost
```
**Fix:** Move `group_vars` and `host_vars` into the `inventory/` directory, or symlink them there. Alternatively, configure `ansible.cfg` or inventory path to correctly resolve these directories relative to the playbook.

### 2. Missing Python Dependencies for Docker
**Severity:** Medium
**Description:** The `community.docker` collection requires `requests` and `docker` Python packages on the target machine. These are not installed by `setup.sh` (which only installs Ansible).
**Fix:** Update `setup.sh` or the `docker_install` role to ensure `python3-requests` and `python3-docker` (or pip equivalents) are installed before using Docker modules.

### 3. Ansible Lint Violations
**Severity:** Low (Code Quality)
**Count:** 553 violations
**Description:** `ansible-lint` found numerous issues, primarily:
- **FQCN:** Modules should use Fully Qualified Collection Names (e.g., `ansible.builtin.file` instead of `file`).
- **Variable Naming:** Variables in roles should use the role name as a prefix.
- **Formatting:** Trailing spaces, indentation, etc.
- **Risky Shell Pipe:** Shell commands with pipes should check for failure (`pipefail`).

### 4. Syntax Warning
**Severity:** Low
**Description:** A reserved variable name `port` is used in `roles/tshark_tools/defaults/main.yml`.
```
[WARNING]: Found variable using reserved name 'port'.
Origin: /app/roles/tshark_tools/defaults/main.yml:4:1
```

### 5. Check Mode (Dry Run) Failures
**Severity:** Low (Operational)
**Description:** The playbook fails in check mode (`--check`) because some tasks (like setting permissions on WireGuard keys) depend on files that are created by previous tasks. In check mode, these files are not created, causing subsequent tasks to fail.

## Recommendations
1.  **Fix Structure:** Move `group_vars` and `host_vars` to `inventory/` to ensure they are picked up regardless of where the playbook is run from.
2.  **Lint Fixes:** Run `ansible-lint --fix` to automatically resolve some formatting issues, and manually update module names to FQCN.
3.  **Dependencies:** Ensure `requests` and `docker` libraries are installed on targets.
4.  **Rename Variable:** Rename `port` to `tshark_port` or similar in `tshark_tools` role.
