# AUR Supply-Chain Scanner — June 2026

Detection toolkit for the **atomic-lockfile / js-digest** AUR supply-chain incident.

This project combines:

1. **Community scanner** (`lenucksi/aur-malware-check`)
2. **Deep forensic scanner** (`aur-deepcheck.sh`)

The goal is to detect both known compromised packages and post-compromise indicators that are not covered by the community scanner alone.

---

# Files

```text
aur-check.sh
aur-deepcheck.sh
README.md
```

`aur-check.sh` is the main entry point.

It automatically:

- clones or updates `lenucksi/aur-malware-check`
- executes the community scanner
- executes the deep forensic pass
- returns a consolidated verdict

---

# Usage

Recommended:

```bash
sudo ./aur-check.sh
```

Limited mode:

```bash
./aur-check.sh
```

Optional:

```bash
sudo MAX_PID_PROBE=65536 ./aur-check.sh
```

---

# Pass 1 — Community Scanner

Checks:

- known compromised package names
- pacman database
- pacman logs
- npm caches
- bun caches
- known malware indicators
- predefined bpffs locations

Source:

https://github.com/lenucksi/aur-malware-check

---

# Pass 2 — Deep Forensic Scanner

## Section A

Filesystem artifacts:

- monero-wallet-gui
- deps ELF payload
- suspicious unowned binaries

## Section B

AUR helper caches:

- yay
- paru
- pikaur
- trizen
- aurutils
- pacaur

## Section C

pacman local database verification.

## Section D

Live process inspection.

## Section E

Hidden PID detection:

- stat()
- procfs enumeration comparison

## Section F

Kernel BPF enumeration using bpftool.

## Section G

Network consistency checks.

## Section H

systemd persistence review.

## Section I

Journal sweep.

## Section J

SSH material review.

---

# Why Clean Results Matter

A clean result means:

- no malicious package traces
- no cached malicious build artifacts
- no compromised pacman scriptlets
- no active payload process
- no visible rootkit indicators
- no suspicious persistence mechanisms

While no userland scanner can provide absolute guarantees, a fully clean run provides strong evidence that the malicious payload never successfully executed.

---

# Limitations

No userland tool can fully exclude:

- kernel modules
- advanced syscall hooking
- LSM abuse
- firmware persistence
- offline compromise

For high-assurance investigations, use trusted-media offline forensics.

---

# Incident Response

If CRITICAL findings are reported:

1. Disconnect the host immediately.
2. Rotate all credentials from a clean machine.
3. Review SSH keys and authorized_keys.
4. Preserve forensic evidence.
5. Reinstall from trusted media.

---

# Credits

- Arch Linux community
- lenucksi/aur-malware-check
- Incident researchers and analysts documenting the June 2026 compromise
- Claude Fable
- OpenAI ChatGPT 5.5
