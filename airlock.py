#!/usr/bin/env python3
import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from auditor import audit_package
from netwatch import run_with_network_monitor
from ai_shield import scan_package_dir, scan_node_modules

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("airlock")

COLORS = {
    "CRITICAL": "\033[1;31m",
    "HIGH": "\033[0;31m",
    "MEDIUM": "\033[0;33m",
    "LOW": "\033[0;36m",
    "INFO": "\033[0;32m",
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
}


def _detect_package_manager() -> str:
    if Path("pnpm-lock.yaml").exists():
        return "pnpm"
    if Path("bun.lockb").exists() or Path("bun.lock").exists():
        return "bun"
    if Path("yarn.lock").exists():
        return "yarn"
    return "npm"


def _find_pkg_binary(name: str) -> str:
    found = shutil.which(name)
    if found:
        return found
    return name


def _parse_packages_from_args(args: list[str]) -> list[str]:
    packages = []
    skip_next = False
    for a in args:
        if skip_next:
            skip_next = False
            continue
        if a.startswith("-"):
            if a in ("-D", "--save-dev", "-g", "--global", "-E", "--save-exact"):
                continue
            if a in ("-w", "--workspace-root"):
                continue
            skip_next = True
            continue
        packages.append(a)
    return packages


def _parse_lockfile_packages(pm: str) -> set[str]:
    packages = set()
    if pm == "pnpm" and Path("pnpm-lock.yaml").exists():
        try:
            for line in Path("pnpm-lock.yaml").read_text().splitlines():
                line = line.strip()
                if line.startswith("'") or line.startswith('"'):
                    name = line.strip("'\"").split("@")[0].rstrip("/")
                    if name and not name.startswith("."):
                        packages.add(name)
        except OSError:
            pass
    elif pm == "npm" and Path("package-lock.json").exists():
        try:
            lock = json.loads(Path("package-lock.json").read_text())
            for key in lock.get("packages", {}):
                if key.startswith("node_modules/"):
                    packages.add(key[len("node_modules/"):])
        except (OSError, json.JSONDecodeError):
            pass
    return packages


def _colorize(severity: str, text: str) -> str:
    c = COLORS.get(severity.upper(), "")
    return f"{c}{text}{COLORS['RESET']}" if c else text


def cmd_install(args: argparse.Namespace) -> int:
    pm = args.pm or _detect_package_manager()
    pm_bin = _find_pkg_binary(pm)
    packages = _parse_packages_from_args(args.pkg_args)
    clean_install = True
    plugins = _load_plugins()

    logger.info("Package manager: %s", pm)
    logger.info("Packages: %s", packages or "(from lockfile)")

    # Plugin hook: pre_audit
    if not _run_plugin_hook("pre_audit", plugins, pm, packages, args.force):
        return 1

    # Phase 1: Audit packages against registry
    if packages:
        logger.info("--- Phase 1: Package Audit ---")
        any_critical = False
        for pkg in packages:
            name = pkg
            version = None
            if pkg.startswith("@") and pkg.count("@") > 1:
                name, version = pkg.rsplit("@", 1)
            elif not pkg.startswith("@") and "@" in pkg:
                name, version = pkg.rsplit("@", 1)

            audit = audit_package(name, version)
            if audit.risks:
                sev = audit.severity.upper()
                print(f"\n  {_colorize(audit.severity, f'[{sev}]')} {audit.name}@{audit.version}")
                for r in audit.risks:
                    rs = r['severity'].upper()
                    print(f"    {_colorize(r['severity'], f'[{rs}]')} {r['risk']}: {r['detail']}")
                if audit.severity == "critical":
                    any_critical = True
            else:
                print(f"  {_colorize('info', '[OK]')} {audit.name}@{audit.version}")

        if any_critical:
            clean_install = False
            if not args.force:
                logger.critical("Critical risks found. Use --force to install anyway.")
                return 1
            logger.warning("Proceeding despite critical risks (--force)")

    # Plugin hook: post_audit (after registry checks, before install)
    if not _run_plugin_hook("post_audit", plugins, pm, packages, args.force):
        return 1

    # Phase 2: Install with --ignore-scripts
    # Check if a plugin provides an alternative binary (e.g. safe-chain prefix)
    install_prefix = []  # prefix commands (e.g. ["safe-chain"])
    install_bin = pm_bin
    install_bin_plugins = [p for p in plugins if p.phase == "install_binary"]
    for plugin in install_bin_plugins:
        mode = getattr(plugin, "mode", None) or "replace"
        alt_bin = plugin.command.replace("{pm}", pm)
        resolved = shutil.which(alt_bin)
        if resolved:
            if mode == "prefix":
                # Prefix mode: safe-chain expects short pm name (e.g. "safe-chain pnpm add ...")
                logger.info("Plugin '%s': using %s as install prefix", plugin.name, alt_bin)
                install_prefix = [resolved]
                install_bin = pm
            else:
                logger.info("Plugin '%s': using %s as install binary", plugin.name, alt_bin)
                install_bin = resolved
            break
        else:
            logger.warning("Plugin '%s': binary '%s' not found, using default", plugin.name, alt_bin)

    subcmd = getattr(args, "subcmd", "install")
    logger.info("--- Phase 2: %s (scripts disabled) ---", subcmd.capitalize())
    before_packages = _parse_lockfile_packages(pm)

    if subcmd == "update":
        install_cmd = install_prefix + [install_bin, "update", "--ignore-scripts"] + args.pkg_args
    elif pm == "pnpm":
        install_cmd = install_prefix + ([install_bin, "add", "--ignore-scripts"] + args.pkg_args if packages else [install_bin, "install", "--ignore-scripts"])
    else:
        install_cmd = install_prefix + [install_bin, "install", "--ignore-scripts"] + args.pkg_args

    logger.info("Running: %s", " ".join(install_cmd))
    result = subprocess.run(install_cmd, text=True)
    if result.returncode != 0:
        logger.error("Install failed with exit code %d", result.returncode)
        return result.returncode

    # Plugin hook: post_install (after install, before AI scan)
    if not _run_plugin_hook("post_install", plugins, pm, packages, args.force):
        return 1

    # Phase 3: AI injection scan on new packages
    logger.info("--- Phase 3: AI Injection Scan ---")
    after_packages = _parse_lockfile_packages(pm)
    new_packages = after_packages - before_packages
    scan_targets = list(new_packages) if new_packages else packages

    if scan_targets:
        logger.info("Scanning %d package(s) for AI-targeted threats...", len(scan_targets))
        ai_results = scan_node_modules(Path("."), scan_targets)
        any_ai_threat = False
        for pkg_name, scan in ai_results.items():
            if scan.threats:
                any_ai_threat = True
                print(f"\n  {_colorize('critical', '[AI THREAT]')} {pkg_name}")
                for t in scan.threats[:10]:
                    ts = t.severity.upper()
                    print(f"    {_colorize(t.severity, f'[{ts}]')} {t.threat_type}: {t.detail}")
                    if t.snippet:
                        print(f"           {COLORS['DIM']}{t.snippet}{COLORS['RESET']}")
                if len(scan.threats) > 10:
                    print(f"    ... and {len(scan.threats) - 10} more")
            elif scan.ai_config_files:
                print(f"  {_colorize('high', '[WARN]')} {pkg_name}: AI config files found: {scan.ai_config_files}")

        if any_ai_threat:
            clean_install = False
            if not args.force:
                logger.critical("AI-targeted threats detected! Use --force to continue.")
                return 1
    else:
        logger.info("No new packages to scan")

    # Phase 4: Run postinstall scripts under network monitoring
    # Clean install: run all scripts under monitor mode (transparent to dev)
    # Dirty install (--force): only allowlisted scripts, sandbox mode
    logger.info("--- Phase 4: Post-install Scripts (monitored) ---")
    allowed = _load_script_allowlist()
    scripts_to_run = []

    nm = Path("node_modules")
    run_targets = list(new_packages) if new_packages else packages
    for pkg in run_targets:
        pkg_dir = nm / pkg
        pkg_json = pkg_dir / "package.json"
        if not pkg_json.exists():
            continue
        try:
            pdata = json.loads(pkg_json.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        scripts = pdata.get("scripts", {})
        for hook in ("preinstall", "install", "postinstall"):
            if hook in scripts:
                if clean_install or pkg in allowed:
                    scripts_to_run.append((pkg, hook, scripts[hook]))
                else:
                    logger.warning("BLOCKED %s:%s — flagged + not in allowlist (add to .airlock-allow.json)", pkg, hook)

    use_sandbox = not clean_install and not args.no_sandbox
    if scripts_to_run:
        for pkg, hook, script_content in scripts_to_run:
            mode = "sandbox" if use_sandbox else "network monitor"
            logger.info("Running %s:%s under %s...", pkg, hook, mode)
            run_cmd = [pm_bin, "rebuild", pkg] if hook == "install" else ["sh", "-c", script_content]
            net_result = run_with_network_monitor(
                run_cmd,
                use_strace=not args.no_strace,
                sandbox=use_sandbox,
                timeout=args.script_timeout,
            )
            if net_result.suspicious_events:
                print(f"\n  {_colorize('critical', '[NET ALERT]')} {pkg}:{hook}")
                for evt in net_result.suspicious_events:
                    d = evt.to_dict()
                    print(f"    \u2192 {d['remote']} \u2014 {d.get('reason', 'suspicious')}")
                if not args.force:
                    logger.critical("Suspicious network activity during %s:%s", pkg, hook)
                    return 1
            else:
                logger.info("%s:%s \u2014 %s", pkg, hook, net_result.summary)
    elif any(True for pkg in run_targets for hook in ("preinstall", "install", "postinstall")
             if (nm / pkg / "package.json").exists()):
        logger.info("No allowlisted scripts to run. Packages with scripts were blocked.")
    else:
        logger.info("No post-install scripts needed")

    # Plugin hook: post_scan (after all phases complete)
    _run_plugin_hook("post_scan", plugins, pm, packages, args.force)

    print(f"\n{_colorize('info', '[DONE]')} Installation complete.")
    return 0


def _extract_exec_packages(exec_args: list[str]) -> list[str]:
    explicit = []
    it = iter(exec_args)
    for a in it:
        if a in ("-p", "--package"):
            pkg = next(it, None)
            if pkg:
                explicit.append(pkg)
            continue
        if a.startswith("-"):
            continue
        if explicit:
            break
        return [a]
    return explicit


def cmd_exec(args: argparse.Namespace) -> int:
    exec_args = args.exec_args or []
    packages = _extract_exec_packages(exec_args)

    if not packages:
        logger.warning("No package detected in exec args, passing through")
        result = subprocess.run(exec_args)
        return result.returncode

    logger.info("Exec pre-flight audit for: %s", packages)
    any_critical = False
    for pkg in packages:
        name = pkg
        version = None
        if pkg.startswith("@") and pkg.count("@") > 1:
            name, version = pkg.rsplit("@", 1)
        elif not pkg.startswith("@") and "@" in pkg:
            name, version = pkg.rsplit("@", 1)

        audit = audit_package(name, version)
        if audit.risks:
            sev = audit.severity.upper()
            print(f"\n  {_colorize(audit.severity, f'[{sev}]')} {audit.name}@{audit.version}")
            for r in audit.risks:
                rs = r["severity"].upper()
                print(f"    {_colorize(r['severity'], f'[{rs}]')} {r['risk']}: {r['detail']}")
            if audit.severity == "critical":
                any_critical = True
        else:
            print(f"  {_colorize('info', '[OK]')} {audit.name}@{audit.version}")

    if any_critical and not args.force:
        logger.critical("Critical risks found. Use --force to run anyway.")
        return 1

    logger.info("Audit passed, running: %s", " ".join(exec_args))
    result = subprocess.run(exec_args)
    return result.returncode


def cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.path) if args.path else Path(".")
    packages = args.packages if args.packages else None

    logger.info("Scanning %s for AI-targeted threats...", target)
    results = scan_node_modules(target, packages)

    total_threats = 0
    for pkg_name, scan in sorted(results.items()):
        if scan.threats:
            sev = "critical" if any(t.severity == "critical" for t in scan.threats) else "high"
            print(f"\n  {_colorize(sev, f'[{sev.upper()}]')} {pkg_name} \u2014 {scan.summary}")
            for t in scan.threats[:5]:
                ts = t.severity.upper()
                print(f"    {_colorize(t.severity, f'[{ts}]')} {t.threat_type}: {t.detail}")
                if t.snippet:
                    print(f"           {COLORS['DIM']}{t.snippet}{COLORS['RESET']}")
            if len(scan.threats) > 5:
                print(f"    ... and {len(scan.threats) - 5} more")
            total_threats += len(scan.threats)
        elif args.verbose:
            print(f"  {_colorize('info', '[OK]')} {pkg_name} \u2014 {scan.summary}")

    print(f"\nScanned {len(results)} packages, {total_threats} threat(s) found.")
    return 1 if total_threats > 0 else 0


def cmd_audit(args: argparse.Namespace) -> int:
    for pkg_spec in args.packages:
        name = pkg_spec
        version = None
        if pkg_spec.startswith("@") and pkg_spec.count("@") > 1:
            name, version = pkg_spec.rsplit("@", 1)
        elif not pkg_spec.startswith("@") and "@" in pkg_spec:
            name, version = pkg_spec.rsplit("@", 1)

        logger.info("Auditing %s...", pkg_spec)
        result = audit_package(name, version)
        sev = result.severity.upper()
        print(f"\n  {_colorize(result.severity, f'[{sev}]')} {result.name}@{result.version}")
        if result.risks:
            for r in result.risks:
                rs = r["severity"].upper()
                print(f"    {_colorize(r['severity'], f'[{rs}]')} {r['risk']}: {r['detail']}")
        else:
            print(f"    No risks identified")
    return 0


def _load_script_allowlist() -> set[str]:
    allow_file = Path(".airlock-allow.json")
    if not allow_file.exists():
        return set()
    try:
        data = json.loads(allow_file.read_text())
        return set(data.get("allow_scripts", []))
    except (OSError, json.JSONDecodeError):
        return set()


@dataclass
class PluginHook:
    name: str
    phase: str
    command: str
    args: list[str] = field(default_factory=list)
    blocking: bool = True
    enabled: bool = True
    mode: str = "replace"


def _load_plugins() -> list[PluginHook]:
    """Load plugin definitions from .airlock-plugins.json or ~/.config/airlock/plugins.json"""
    candidates = [
        Path(".airlock-plugins.json"),
        Path.home() / ".config" / "airlock" / "plugins.json",
    ]
    for cfg_path in candidates:
        if cfg_path.exists():
            try:
                data = json.loads(cfg_path.read_text())
                plugins = []
                for entry in data.get("plugins", []):
                    if not entry.get("enabled", True):
                        continue
                    plugins.append(PluginHook(
                        name=entry["name"],
                        phase=entry["phase"],
                        command=entry["command"],
                        args=entry.get("args", []),
                        blocking=entry.get("blocking", True),
                        enabled=True,
                        mode=entry.get("mode", "replace"),
                    ))
                if plugins:
                    logger.info("Loaded %d plugin(s) from %s", len(plugins), cfg_path)
                return plugins
            except (OSError, json.JSONDecodeError, KeyError) as e:
                logger.warning("Failed to load plugins from %s: %s", cfg_path, e)
    return []


def _run_plugin_hook(
    phase: str,
    plugins: list[PluginHook],
    pm: str,
    packages: list[str],
    force: bool = False,
) -> bool:
    """Run all plugins registered for a given phase. Returns False if a blocking plugin fails."""
    phase_plugins = [p for p in plugins if p.phase == phase]
    if not phase_plugins:
        return True

    for plugin in phase_plugins:
        cmd_str = plugin.command
        # Template substitution
        cmd_str = cmd_str.replace("{pm}", pm)
        cmd_str = cmd_str.replace("{packages}", " ".join(packages))

        full_args = cmd_str.split() + [
            a.replace("{pm}", pm).replace("{packages}", " ".join(packages))
            for a in plugin.args
        ]

        # Verify binary exists
        if not shutil.which(full_args[0]):
            logger.warning("Plugin '%s': binary '%s' not found, skipping", plugin.name, full_args[0])
            continue

        logger.info("--- Plugin: %s [%s] ---", plugin.name, phase)
        logger.info("Running: %s", " ".join(full_args))

        result = subprocess.run(full_args)
        if result.returncode != 0:
            if plugin.blocking and not force:
                logger.critical(
                    "Plugin '%s' failed (exit %d). Use --force to override.",
                    plugin.name, result.returncode,
                )
                return False
            logger.warning(
                "Plugin '%s' failed (exit %d), continuing (--force or non-blocking)",
                plugin.name, result.returncode,
            )

    return True


KNOWN_PLUGINS = {
    "aikido": {
        "name": "aikido",
        "phase": "install_binary",
        "command": "safe-chain",
        "blocking": True,
        "enabled": True,
        "mode": "prefix",
        "description": "Aikido Safe Chain — malware database scanning during install",
        "check_binary": "safe-chain",
        "install_hint": "curl -fsSL https://github.com/AikidoSec/safe-chain/releases/latest/download/install-safe-chain.sh | sh",
    },
}


def _plugins_config_path() -> Path:
    return Path.home() / ".config" / "airlock" / "plugins.json"


def _read_plugins_config() -> dict:
    cfg = _plugins_config_path()
    if cfg.exists():
        try:
            return json.loads(cfg.read_text())
        except (OSError, json.JSONDecodeError):
            pass
    return {"plugins": []}


def _write_plugins_config(data: dict) -> None:
    cfg = _plugins_config_path()
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(json.dumps(data, indent=2) + "\n")


def cmd_plugin(args: argparse.Namespace) -> int:
    action = args.action

    if action == "list":
        config = _read_plugins_config()
        plugins = config.get("plugins", [])
        if not plugins:
            print("No plugins configured.")
            print(f"\nAvailable: {', '.join(KNOWN_PLUGINS.keys())}")
            print("Add one with: airlock plugin add <name>")
            return 0
        print(f"{'Name':<15} {'Phase':<16} {'Command':<20} {'Enabled'}")
        print("-" * 65)
        for p in plugins:
            enabled = "yes" if p.get("enabled", True) else "no"
            print(f"{p['name']:<15} {p['phase']:<16} {p['command']:<20} {enabled}")
        return 0

    if action == "add":
        plugin_name = args.plugin_name
        if not plugin_name:
            print("Usage: airlock plugin add <name>")
            print(f"Available: {', '.join(KNOWN_PLUGINS.keys())}")
            return 1

        config = _read_plugins_config()
        existing = [p["name"] for p in config.get("plugins", [])]
        if plugin_name in existing:
            print(f"Plugin '{plugin_name}' is already configured.")
            return 0

        if plugin_name in KNOWN_PLUGINS:
            preset = KNOWN_PLUGINS[plugin_name]

            # Check if binary is available
            check_bin = preset.get("check_binary")
            if check_bin and shutil.which(check_bin):
                print(f"  Detected: {check_bin}")
            elif check_bin:
                print(f"  Warning: '{check_bin}' not found on PATH.")
                print(f"  Install with: {preset['install_hint']}")
                print(f"  Adding plugin anyway (will be skipped at runtime if binary missing).\n")

            entry = {
                "name": preset["name"],
                "phase": preset["phase"],
                "command": preset["command"],
                "mode": preset.get("mode", "replace"),
                "blocking": preset["blocking"],
                "enabled": preset["enabled"],
            }
            config.setdefault("plugins", []).append(entry)
            _write_plugins_config(config)
            print(f"  Added plugin: {plugin_name}")
            print(f"  Description: {preset['description']}")
            print(f"  Command: {preset['command']} ({preset.get('mode', 'replace')} mode)")
        else:
            print(f"Unknown plugin '{plugin_name}'.")
            print(f"Available presets: {', '.join(KNOWN_PLUGINS.keys())}")
            print("\nTo add a custom plugin, edit ~/.config/airlock/plugins.json directly.")
            return 1

        return 0

    if action == "remove":
        plugin_name = args.plugin_name
        if not plugin_name:
            print("Usage: airlock plugin remove <name>")
            return 1

        config = _read_plugins_config()
        before = len(config.get("plugins", []))
        config["plugins"] = [p for p in config.get("plugins", []) if p["name"] != plugin_name]
        after = len(config["plugins"])

        if before == after:
            print(f"Plugin '{plugin_name}' not found in config.")
            return 1

        _write_plugins_config(config)
        print(f"  Removed plugin: {plugin_name}")
        return 0

    print("Usage: airlock plugin <list|add|remove> [name]")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="airlock",
        description="Secure package installation with AI threat detection and network monitoring",
    )
    sub = parser.add_subparsers(dest="command")

    p_install = sub.add_parser("install", help="Install packages securely")
    p_install.add_argument("pkg_args", nargs="*", help="Packages and flags to pass to package manager")
    p_install.add_argument("--pm", choices=["npm", "pnpm", "yarn", "bun"], help="Package manager (auto-detected)")
    p_install.add_argument("--subcmd", default="install", help=argparse.SUPPRESS)
    p_install.add_argument("--force", action="store_true", help="Install even with critical risks")
    p_install.add_argument("--no-sandbox", action="store_true", help="Don't use bwrap sandbox (monitor only)")
    p_install.add_argument("--no-strace", action="store_true", help="Use connection diffing instead of strace")
    p_install.add_argument("--script-timeout", type=int, default=300, help="Timeout for post-install scripts")
    p_install.set_defaults(func=cmd_install)

    p_scan = sub.add_parser("scan", help="Scan node_modules for AI-targeted threats")
    p_scan.add_argument("--path", help="Project directory (default: current)")
    p_scan.add_argument("--packages", nargs="*", help="Specific packages to scan")
    p_scan.add_argument("--verbose", "-v", action="store_true", help="Show clean packages too")
    p_scan.set_defaults(func=cmd_scan)

    p_exec = sub.add_parser("exec", help="Run npx/bunx/dlx with pre-flight audit")
    p_exec.add_argument("exec_args", nargs="*", help="Command to run (e.g., npx create-react-app)")
    p_exec.add_argument("--force", action="store_true", help="Run even with critical risks")
    p_exec.set_defaults(func=cmd_exec)

    p_audit = sub.add_parser("audit", help="Audit specific packages against registry")
    p_audit.add_argument("packages", nargs="+", help="Package names to audit")
    p_audit.set_defaults(func=cmd_audit)

    p_plugin = sub.add_parser("plugin", help="Manage security plugins")
    p_plugin.add_argument("action", nargs="?", default="list", choices=["list", "add", "remove"],
                          help="Action to perform (default: list)")
    p_plugin.add_argument("plugin_name", nargs="?", default=None, help="Plugin name")
    p_plugin.set_defaults(func=cmd_plugin)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
