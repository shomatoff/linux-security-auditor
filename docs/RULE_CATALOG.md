# Rule catalog

Each rule has a stable ID. `UNKNOWN` means evidence was unavailable; `NOT_APPLICABLE` means the check did not apply. PASS is **rule-local**, not a host security score.

| ID | Category | Evidence | Interpretation |
|---|---|---|---|
| OS-001 | Host | `/etc/os-release` ID/version | PASS for validated Ubuntu 22.04/24.04 or Debian 12; otherwise NOT_APPLICABLE. |
| SSH-001 | SSH | `systemctl is-active ssh.service`, sshd presence | Inventory. Active is PASS/INFO, absent is NOT_APPLICABLE. |
| SSH-002 | SSH | `PermitRootLogin` from effective `sshd -T` when conclusive | `no` PASS, limited modes WARN, `yes` FAIL. |
| SSH-003 | SSH | `PasswordAuthentication` | `no` PASS, `yes` WARN. |
| SSH-004 | SSH | `PermitEmptyPasswords` | `no` PASS, `yes` FAIL. |
| SSH-005 | SSH | `X11Forwarding` | `no` PASS, `yes` WARN. |
| SSH-006 | SSH | `MaxAuthTries` | 1–4 PASS, larger values WARN; invalid UNKNOWN. |
| FW-001 | Firewall | `ufw status verbose` | Observed active UFW with default deny incoming PASS; active with other default WARN; inactive FAIL. Unreadable policy UNKNOWN. A running firewalld daemon is UNKNOWN. This is not proof that all traffic is blocked. |
| ACC-001 | Accounts | `/etc/passwd` metadata | Non-root UID 0 accounts FAIL; none PASS. |
| ACC-002 | Accounts | `/etc/group` sudo/wheel listed members | Inventory only, PASS/INFO does not approve membership. |
| UPD-001 | Updates | Local `apt list --upgradable` + cache age | Pending WARN; zero with cache older than seven days UNKNOWN; zero with fresher cache PASS with stale-data caveat. |
| UPD-002 | Updates | `20auto-upgrades` configuration | Enabled PASS, disabled WARN; never claims successful installations. |
| PERM-001 | Permissions | Optional selected directory `lstat`/`scandir` | World-writable entries FAIL; none PASS only if scan complete. Partial/bounded results UNKNOWN when none found. |

SSH `Include` or `Match` makes global policy context dependent; this version marks setting checks UNKNOWN rather than promoting a possibly misleading `sshd -T` value. A non-running SSH service makes configuration checks NOT_APPLICABLE. The rule engine is deterministic and independently tested.
