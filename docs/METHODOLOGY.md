# Methodology and confidence

1. The user starts a local scan. The collector reads `/etc/os-release`, safe account/group metadata, SSH/firewall status, local APT metadata, automatic update configuration, and only the optional directory the user selected.
2. Each collected fact carries a state (`OK`, `UNKNOWN`, `NOT_APPLICABLE`), source and limitation. Missing commands, denied access, stale cache and ambiguous SSH context are retained as limitations.
3. Pure rules map evidence to findings. No aggregate security score is produced. `PASS` covers one rule and never certifies a machine.
4. The UI and reports render the same result with localized text. JSON retains machine-readable status codes. Default report redaction hides a selected directory path. No report is uploaded.

A local scan cannot establish exposure to a remote attacker, verify all effective nftables rules without privilege, confirm security updates were installed, or analyze private material. The application does not run `sudo`, `apt update`, firewall changes, user changes, intrusion tests or network requests. Suggested remediation is text for human review.

The tested rule target is Ubuntu 22.04/24.04 and Debian 12. Other Linux systems may still show inventory, but OS-001 states that the rule set is outside validated scope. The directory scan stops at 250 entries and depth 2, skips symlinks, and treats partial coverage conservatively.

Reference material: [OpenSSH `sshd_config` manual](https://man.openbsd.org/sshd_config), [Ubuntu firewall documentation](https://documentation.ubuntu.com/server/how-to/security/firewalls/), [Ubuntu automatic updates](https://documentation.ubuntu.com/server/how-to/software/automatic-updates/).
