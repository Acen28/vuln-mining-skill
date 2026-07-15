# vuln-hunting

Universal vulnerability hunting methodology: sink-to-source binary analysis, API fuzzing, protocol reversal, SSRF hunting, IPC mapping, and PoC development. Works on any target — IoT firmware, web applications, embedded Linux, Android, desktop binaries.

## Files

| File | Purpose |
|------|---------|
| `SKILL.md` | Full methodology (Phase 0-7) |
| `headers.txt` | AI prompt header — prepend to new sessions |
| `toolkit.py` | Python utility functions for common tasks |
| `fuzz_api.py` | API fuzzing script — plug in targets and payloads |
| `qa.md` | Common failure modes and fixes |

## Quick Start

1. Copy this folder to your workspace.
2. In a new session, reference `SKILL.md` by saying "use the vuln-hunting skill".
3. Or prepend `headers.txt` as custom instructions.
4. Import `toolkit.py` functions as needed.

## Key Principles

- **Sink before source**: Find system()/popen()/strcpy() first, THEN trace backward.
- **Emulate early**: QEMU user-mode is 100x faster than hardware iterations.
- **Build bridges**: Most internal vulnerabilities need a "bridge" (SSRF, IPC, proxy).
- **Evidence quality > quantity**: One function decompilation at a verified address beats ten pages of prose.
