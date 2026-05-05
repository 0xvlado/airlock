# Changelog

## [Unreleased]

### Added
- **Plugin system** — external security tools can hook into airlock's install pipeline via `.airlock-plugins.json` (per-project) or `~/.config/airlock/plugins.json` (global)
- **Aikido Safe Chain integration** — `install_binary` plugin phase allows aikido-wrapped binaries to handle the actual install, combining both tools' security scanning
- **Plugin auto-detection in setup.sh** — automatically creates plugins config if `aikido-npm`/`aikido-pnpm` binaries are found on PATH
- **`airlock plugin` command** — helper to list, add, and remove plugins without editing JSON manually
- Plugin hook phases: `pre_audit`, `post_audit`, `install_binary`, `post_install`, `post_scan`
- Template variables `{pm}` and `{packages}` in plugin commands

### Changed
- `cmd_install` now loads plugins and runs hook phases throughout the pipeline
- Phase 2 (install) can use an alternative binary provided by an `install_binary` plugin

## [0.1.0] - 2026-05-04

### Added
- Initial release
- Four-phase install pipeline: registry audit, safe install, AI threat scan, network monitoring
- Shell hook intercepting npm, pnpm, yarn, bun, npx, bunx
- AI injection scanner (prompt injection, zero-width chars, obfuscated eval, AI config files)
- Network monitoring via strace (Linux) and connection diffing
- Bubblewrap sandbox for flagged postinstall scripts
- Registry audit: typosquatting, publish age, maintainer changes, suspicious scripts
- `airlock install`, `airlock exec`, `airlock scan`, `airlock audit` commands
- Per-project `.airlock-allow.json` and `.airlock-ignore.json` configs
- Anti-tampering file locking (`chattr +i` / `chflags uchg`)
- 249 unit tests
