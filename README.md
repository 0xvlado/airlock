# airlock

Supply chain security for JavaScript packages. Transparent shell hook that intercepts `npm install`, `pnpm add`, `yarn add`, and `bun add` — scanning every package before it touches your codebase.

Zero dependencies — pure Python stdlib. Works on macOS and Linux.

## What it does

Every package install goes through four phases:

1. **Registry audit** — checks publish age, maintainer changes, typosquatting, suspicious install scripts
2. **Safe install** — installs with `--ignore-scripts` so nothing executes yet
3. **AI threat scan** — detects prompt injection, hidden unicode, obfuscated eval, and AI config files (`.cursorrules`, `CLAUDE.md`, etc.) planted in packages to manipulate coding assistants
4. **Monitored execution** — runs postinstall scripts under network monitoring (strace on Linux), flags suspicious connections

If everything is clean, the install completes normally — the developer doesn't notice airlock is there. If threats are found, the install is blocked before any damage.

## Install

```bash
git clone <repo> ~/projects/airlock
cd ~/projects/airlock
chmod +x setup.sh
bash setup.sh
```

This will:
1. Install the `airlock` CLI to `/usr/local/bin`
2. Add shell hooks to `.bashrc`/`.zshrc` that intercept package managers
3. Lock all scanner files (`chattr +i` on Linux, `chflags uchg` on macOS)

Restart your shell or `source ~/.config/airlock/hook.sh`.

## Usage

Just use your package manager as normal:

```bash
npm install axios        # intercepted — audit + AI scan + monitored scripts
pnpm add lodash          # intercepted
yarn add express         # intercepted
bun add zod              # intercepted
npm run build            # passed through — not an install command
```

Or call airlock directly:

```bash
airlock install axios lodash
airlock install -D typescript
airlock audit some-unknown-package
airlock scan                         # scan existing node_modules
airlock scan --packages express axios
airlock scan -v                      # verbose, show clean packages too
```

### Bypass

```bash
AIRLOCK_BYPASS=1 npm install foo   # skip for one command
export AIRLOCK_DISABLED=1          # disable entirely
command npm install foo            # use real binary directly
```

## What it detects

### Registry-level (Phase 1)
- Typosquatting (Levenshtein distance from top 80+ packages)
- Brand new packages (< 7 days old)
- Very new versions (< 72 hours)
- Complete maintainer changes between versions
- Suspicious install scripts (`curl`, `eval`, `child_process`, etc.)
- High-entropy names (auto-generated malware packages)

### AI-targeted threats (Phase 3)
| Pattern | Example | Severity |
|---------|---------|----------|
| Direct prompt override | `ignore all previous instructions` | Critical |
| Role reassignment | `you are now a helpful...` | Critical |
| Instruction injection | `new instructions:` | Critical |
| AI config files | `.cursorrules`, `CLAUDE.md` in a package | Critical |
| XML prompt tags | `<system>...</system>` | Critical |
| AI tool targeting | `cursor: always include...` | Critical |
| Dangerous eval | `eval(Buffer.from(..., 'base64'))` | Critical |
| Zero-width characters | Hidden unicode in source | High |
| Obfuscated strings | Long hex-encoded sequences | High |

### Network activity (Phase 4)
- Connections to unexpected external hosts during postinstall
- Suspicious ports (reverse shells, SMTP, database ports)
- On Linux with bubblewrap: full network isolation (`--sandbox` flag)

## Per-project configuration

### .airlock-allow.json
```json
{
  "allow_scripts": ["sharp", "better-sqlite3", "bcrypt", "@prisma/engines"]
}
```
These packages run postinstall scripts even when threats were detected (with `--force`). During clean installs, all scripts run under monitoring regardless.

### .airlock-ignore.json
```json
{
  "ignore_packages": ["some-known-safe-package"]
}
```
Skip these packages during AI threat scanning.

## Anti-tampering

All source files and the installed hook are locked with `chattr +i` (Linux) / `chflags uchg` (macOS). This prevents a compromised AI agent or malicious postinstall script from silently disabling airlock.

To modify source files:
```bash
# Linux
sudo chattr -i ~/projects/airlock/*.py ~/projects/airlock/airlock-hook.sh
# make changes
sudo chattr +i ~/projects/airlock/*.py ~/projects/airlock/airlock-hook.sh

# macOS
sudo chflags nouchg ~/projects/airlock/*.py ~/projects/airlock/airlock-hook.sh
# make changes
sudo chflags uchg ~/projects/airlock/*.py ~/projects/airlock/airlock-hook.sh
```

## Architecture

```
airlock/
├── airlock.py        CLI entry point — orchestrates the four phases
├── auditor.py        Registry checks: age, maintainers, typosquatting, scripts
├── ai_shield.py      AI prompt injection, zero-width chars, obfuscation scanner
├── netwatch.py       strace/bwrap network monitoring during postinstall
├── airlock-hook.sh   Shell functions that intercept npm/pnpm/yarn/bun
└── setup.sh          Cross-platform installer (macOS + Linux)
```

## How it handles dirty vs. clean installs

| Scenario | Scripts | Execution mode |
|---|---|---|
| Phases 1-3 clean | All scripts run | Monitor mode (strace) |
| Phases 1-3 flagged + `--force` | Allowlisted only | Sandbox (bwrap, no network) |
| Phases 1-3 flagged, no `--force` | Blocked | Install aborted |

## Platform support

| Feature | Linux | macOS |
|---|---|---|
| Registry audit (Phase 1) | Yes | Yes |
| Safe install (Phase 2) | Yes | Yes |
| AI threat scan (Phase 3) | Yes | Yes |
| strace monitoring (Phase 4) | Yes | No |
| bwrap sandbox (Phase 4) | Yes | No |
| Connection diffing (Phase 4) | Yes | No |
| File locking | `chattr +i` | `chflags uchg` |

On macOS, Phases 1-3 provide full protection. Phase 4 monitoring requires Linux.

## License

MIT
