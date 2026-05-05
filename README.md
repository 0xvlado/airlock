# airlock

Supply chain security for JavaScript packages. Transparent shell hook that intercepts `npm install`, `pnpm add`, `yarn add`, `bun add`, `npx`, `bunx`, and `npm update` — scanning every package before it touches your codebase.

Zero dependencies — pure Python stdlib. Works on macOS and Linux.

## What it does

### Install / Update

Every `install` or `update` command goes through four phases:

1. **Registry audit** — checks publish age, maintainer changes, typosquatting, suspicious install scripts
2. **Safe install** — installs with `--ignore-scripts` so nothing executes yet
3. **AI threat scan** — detects prompt injection, hidden unicode, obfuscated eval, and AI config files (`.cursorrules`, `CLAUDE.md`, etc.) planted in packages to manipulate coding assistants
4. **Monitored execution** — runs postinstall scripts under network monitoring (strace on Linux), flags suspicious connections

If everything is clean, the install completes normally — the developer doesn't notice airlock is there. If threats are found, the install is blocked before any damage.

### Exec (npx / bunx / pnpm dlx)

Exec commands (`npx`, `bunx`, `pnpm dlx`) run a pre-flight registry audit on the package before executing. Critical risks block execution unless `--force` is used.

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
npm update               # intercepted — scans updated packages
pnpm upgrade             # intercepted
npx create-react-app     # intercepted — pre-flight audit before execution
bunx degit user/repo     # intercepted
npm run build            # passed through — not an install/exec command
```

Or call airlock directly:

```bash
airlock install axios lodash
airlock install -D typescript
airlock install --pm pnpm --subcmd update   # run as update
airlock exec -- npx create-react-app my-app
airlock exec -- bunx degit user/repo
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

| Pattern                | Example                                  | Severity |
| ---------------------- | ---------------------------------------- | -------- |
| Direct prompt override | `ignore all previous instructions`       | Critical |
| Role reassignment      | `you are now a helpful...`               | Critical |
| Instruction injection  | `new instructions:`                      | Critical |
| AI config files        | `.cursorrules`, `CLAUDE.md` in a package | Critical |
| XML prompt tags        | `<system>...</system>`                   | Critical |
| AI tool targeting      | `cursor: always include...`              | Critical |
| Dangerous eval         | `eval(Buffer.from(..., 'base64'))`       | Critical |
| Zero-width characters  | Hidden unicode in source                 | High     |
| Obfuscated strings     | Long hex-encoded sequences               | High     |

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

## Plugins

Airlock supports external security tools via a plugin system. Plugins are defined in `.airlock-plugins.json` (per-project) or `~/.config/airlock/plugins.json` (global).

### Plugin phases

| Phase            | When it runs                      | Use case                         |
| ---------------- | --------------------------------- | -------------------------------- |
| `pre_audit`      | Before Phase 1 (registry audit)   | Pre-flight checks                |
| `post_audit`     | After Phase 1, before install     | Additional scanning              |
| `install_binary` | Replaces the pm binary in Phase 2 | Use wrapped binary (e.g. aikido) |
| `post_install`   | After install, before AI scan     | Post-install verification        |
| `post_scan`      | After all phases complete         | Reporting, notifications         |

### Plugin config format

```json
{
  "plugins": [
    {
      "name": "aikido",
      "phase": "install_binary",
      "command": "aikido-{pm}",
      "blocking": true,
      "enabled": true
    }
  ]
}
```

### Template variables

| Variable     | Replaced with                                    |
| ------------ | ------------------------------------------------ |
| `{pm}`       | Detected package manager (npm, pnpm, yarn, bun)  |
| `{packages}` | Space-separated list of packages being installed |

### Example: Aikido Safe Chain

With `aikido-pnpm` / `aikido-npm` installed globally via `@aikidosec/safe-chain`, the `install_binary` plugin replaces the raw `pnpm`/`npm` binary with aikido's wrapped version during Phase 2. This means:

1. **Airlock** handles: registry audit, AI threat scan, network monitoring
2. **Aikido** handles: malware database scanning during the actual install

Both tools run their full security checks without interfering with each other.

### Managing plugins via CLI

```bash
airlock plugin list              # show configured plugins
airlock plugin add aikido        # add aikido (auto-detects binary)
airlock plugin remove aikido     # remove aikido
```

The `add` command checks if the required binary exists and warns if not (but still adds the plugin — it will be skipped at runtime if the binary is missing).

## Anti-tampering

All source files and the installed hook are locked with `chattr +i` (Linux) / `chflags uchg` (macOS). This prevents a compromised AI agent or malicious postinstall script from silently disabling airlock.

To unlock files for editing or reinstalling:

```bash
./airlock-lock.sh unlock   # unlock all airlock files
# make changes or run ./setup.sh (setup re-locks automatically)
./airlock-lock.sh lock     # lock again when done
```

## Commands

| Command                           | Description                                    |
| --------------------------------- | ---------------------------------------------- |
| `airlock install [packages...]`   | Install with full four-phase pipeline          |
| `airlock install --subcmd update` | Update packages with audit + scan              |
| `airlock exec -- <command>`       | Pre-flight audit before npx/bunx/dlx execution |
| `airlock audit <packages...>`     | Audit packages against the npm registry        |
| `airlock scan`                    | Scan existing node_modules for AI threats      |
| `airlock plugin list`             | Show configured plugins                        |
| `airlock plugin add <name>`       | Add a known plugin (e.g. aikido)               |
| `airlock plugin remove <name>`    | Remove a plugin                                |

### Flags

| Flag                          | Commands      | Description                                    |
| ----------------------------- | ------------- | ---------------------------------------------- |
| `--force`                     | install, exec | Proceed despite critical risks                 |
| `--pm <npm\|pnpm\|yarn\|bun>` | install       | Override package manager auto-detection        |
| `--no-sandbox`                | install       | Disable bwrap sandbox, monitor only            |
| `--no-strace`                 | install       | Use connection diffing instead of strace       |
| `--script-timeout <seconds>`  | install       | Timeout for postinstall scripts (default: 300) |
| `--packages <names...>`       | scan          | Scan specific packages only                    |
| `--verbose` / `-v`            | scan          | Show clean packages too                        |

## Architecture

```
airlock/
├── airlock.py        CLI entry point — orchestrates install, exec, scan, audit
├── auditor.py        Registry checks: age, maintainers, typosquatting, scripts
├── ai_shield.py      AI prompt injection, zero-width chars, obfuscation scanner
├── netwatch.py       strace/bwrap network monitoring during postinstall
├── airlock-hook.sh   Shell functions that intercept npm/pnpm/yarn/bun/npx/bunx
├── setup.sh          Cross-platform installer (macOS + Linux)
├── airlock-lock.sh   Lock/unlock helper for immutable files
└── tests/            249 unit tests
```

## How it handles dirty vs. clean installs

| Scenario                         | Scripts          | Execution mode              |
| -------------------------------- | ---------------- | --------------------------- |
| Phases 1-3 clean                 | All scripts run  | Monitor mode (strace)       |
| Phases 1-3 flagged + `--force`   | Allowlisted only | Sandbox (bwrap, no network) |
| Phases 1-3 flagged, no `--force` | Blocked          | Install aborted             |

## Platform support

| Feature                      | Linux       | macOS          |
| ---------------------------- | ----------- | -------------- |
| Registry audit (Phase 1)     | Yes         | Yes            |
| Safe install (Phase 2)       | Yes         | Yes            |
| AI threat scan (Phase 3)     | Yes         | Yes            |
| strace monitoring (Phase 4)  | Yes         | No             |
| bwrap sandbox (Phase 4)      | Yes         | No             |
| Connection diffing (Phase 4) | Yes         | No             |
| File locking                 | `chattr +i` | `chflags uchg` |

On macOS, Phases 1-3 provide full protection. Phase 4 monitoring requires Linux.

## Intercepted commands

| Package manager | Install                              | Update                                   | Exec                    |
| --------------- | ------------------------------------ | ---------------------------------------- | ----------------------- |
| npm             | `npm install`, `npm i`               | `npm update`, `npm upgrade`              | `npx`                   |
| pnpm            | `pnpm add`, `pnpm install`, `pnpm i` | `pnpm update`, `pnpm upgrade`, `pnpm up` | `pnpm dlx`, `pnpm exec` |
| yarn            | `yarn add`, `yarn install`, `yarn i` | `yarn upgrade`, `yarn up`                | —                       |
| bun             | `bun add`, `bun install`, `bun i`    | `bun update`                             | `bunx`                  |

All other subcommands (`run`, `build`, `test`, etc.) pass through to the real binary.

## Running tests

Requires Python 3.10+.

```bash
python -m unittest discover tests -v
```

## License

MIT
