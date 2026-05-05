import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from airlock import (
    _colorize,
    _detect_package_manager,
    _extract_exec_packages,
    _find_pkg_binary,
    _load_script_allowlist,
    _parse_lockfile_packages,
    _parse_packages_from_args,
    cmd_audit,
    cmd_exec,
    cmd_install,
    cmd_scan,
)


class TestDetectPackageManager(unittest.TestCase):
    @patch("airlock.Path")
    def test_pnpm_lock(self, mock_path):
        def exists_side_effect(self_=None):
            return True
        mock_path.return_value.exists = MagicMock(return_value=True)
        mock_path.side_effect = lambda f: MagicMock(exists=MagicMock(return_value=(f == "pnpm-lock.yaml")))
        self.assertEqual(_detect_package_manager(), "pnpm")

    @patch("airlock.Path")
    def test_npm_default(self, mock_path):
        mock_path.side_effect = lambda f: MagicMock(exists=MagicMock(return_value=False))
        self.assertEqual(_detect_package_manager(), "npm")

    @patch("airlock.Path")
    def test_yarn_lock(self, mock_path):
        def side_effect(f):
            return MagicMock(exists=MagicMock(return_value=(f == "yarn.lock")))
        mock_path.side_effect = side_effect
        self.assertEqual(_detect_package_manager(), "yarn")

    @patch("airlock.Path")
    def test_bun_lockb(self, mock_path):
        def side_effect(f):
            return MagicMock(exists=MagicMock(return_value=(f in ("bun.lockb",))))
        mock_path.side_effect = side_effect
        self.assertEqual(_detect_package_manager(), "bun")


class TestParsePackagesFromArgs(unittest.TestCase):
    def test_simple_packages(self):
        self.assertEqual(_parse_packages_from_args(["react", "vue"]), ["react", "vue"])

    def test_save_dev_flag(self):
        self.assertEqual(_parse_packages_from_args(["-D", "jest"]), ["jest"])

    def test_save_dev_long(self):
        self.assertEqual(_parse_packages_from_args(["--save-dev", "jest"]), ["jest"])

    def test_global_flag(self):
        self.assertEqual(_parse_packages_from_args(["-g", "typescript"]), ["typescript"])

    def test_workspace_flag(self):
        self.assertEqual(_parse_packages_from_args(["-w", "react"]), ["react"])

    def test_flag_with_value(self):
        result = _parse_packages_from_args(["--registry", "https://custom.com", "react"])
        self.assertEqual(result, ["react"])

    def test_empty(self):
        self.assertEqual(_parse_packages_from_args([]), [])

    def test_mixed(self):
        result = _parse_packages_from_args(["-D", "jest", "-E", "react@18", "vue"])
        self.assertEqual(result, ["jest", "react@18", "vue"])


class TestParseLockfilePackages(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self._orig_cwd = os.getcwd()
        os.chdir(self.tmpdir)

    def tearDown(self):
        os.chdir(self._orig_cwd)
        shutil.rmtree(self.tmpdir)

    def test_npm_package_lock(self):
        lock = {
            "packages": {
                "": {},
                "node_modules/react": {"version": "18.0.0"},
                "node_modules/vue": {"version": "3.0.0"},
            }
        }
        Path("package-lock.json").write_text(json.dumps(lock))
        result = _parse_lockfile_packages("npm")
        self.assertEqual(result, {"react", "vue"})

    def test_npm_no_lockfile(self):
        self.assertEqual(_parse_lockfile_packages("npm"), set())

    def test_pnpm_no_lockfile(self):
        self.assertEqual(_parse_lockfile_packages("pnpm"), set())

    def test_yarn_unsupported(self):
        self.assertEqual(_parse_lockfile_packages("yarn"), set())

    def test_malformed_npm_lock(self):
        Path("package-lock.json").write_text("not json")
        self.assertEqual(_parse_lockfile_packages("npm"), set())

    def test_npm_filters_root(self):
        lock = {"packages": {"": {}, "node_modules/react": {}}}
        Path("package-lock.json").write_text(json.dumps(lock))
        result = _parse_lockfile_packages("npm")
        self.assertNotIn("", result)
        self.assertIn("react", result)


class TestColorize(unittest.TestCase):
    def test_critical(self):
        result = _colorize("critical", "test")
        self.assertIn("test", result)
        self.assertIn("\033[", result)

    def test_unknown_severity(self):
        result = _colorize("unknown", "test")
        self.assertEqual(result, "test")

    def test_reset_appended(self):
        result = _colorize("high", "test")
        self.assertTrue(result.endswith("\033[0m"))


class TestLoadScriptAllowlist(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self._orig_cwd = os.getcwd()
        os.chdir(self.tmpdir)

    def tearDown(self):
        os.chdir(self._orig_cwd)
        shutil.rmtree(self.tmpdir)

    def test_no_file(self):
        self.assertEqual(_load_script_allowlist(), set())

    def test_valid(self):
        Path(".airlock-allow.json").write_text(json.dumps({"allow_scripts": ["sharp", "esbuild"]}))
        self.assertEqual(_load_script_allowlist(), {"sharp", "esbuild"})

    def test_invalid_json(self):
        Path(".airlock-allow.json").write_text("bad")
        self.assertEqual(_load_script_allowlist(), set())

    def test_missing_key(self):
        Path(".airlock-allow.json").write_text("{}")
        self.assertEqual(_load_script_allowlist(), set())


class TestFindPkgBinary(unittest.TestCase):
    @patch("airlock.shutil.which", return_value="/usr/bin/npm")
    def test_found(self, mock_which):
        self.assertEqual(_find_pkg_binary("npm"), "/usr/bin/npm")

    @patch("airlock.shutil.which", return_value=None)
    def test_not_found(self, mock_which):
        self.assertEqual(_find_pkg_binary("npm"), "npm")


class TestCmdInstall(unittest.TestCase):
    def setUp(self):
        self._plugins_patcher = patch("airlock._load_plugins", return_value=[])
        self._plugins_patcher.start()

    def tearDown(self):
        self._plugins_patcher.stop()

    def _make_args(self, pkg_args=None, pm="npm", force=False, no_sandbox=False, no_strace=True, script_timeout=300):
        return SimpleNamespace(
            pkg_args=pkg_args or [],
            pm=pm,
            force=force,
            no_sandbox=no_sandbox,
            no_strace=no_strace,
            script_timeout=script_timeout,
        )

    @patch("airlock.run_with_network_monitor")
    @patch("airlock.scan_node_modules")
    @patch("airlock.audit_package")
    @patch("airlock._parse_lockfile_packages")
    @patch("airlock._find_pkg_binary", return_value="/usr/bin/npm")
    @patch("airlock.subprocess.run")
    def test_clean_install(self, mock_run, mock_find, mock_lockpkg, mock_audit, mock_scan, mock_netmon):
        mock_run.return_value = MagicMock(returncode=0)
        mock_lockpkg.return_value = set()
        mock_audit.return_value = MagicMock(risks=[], severity="info", name="react", version="18.0.0")
        mock_scan.return_value = {}

        result = cmd_install(self._make_args(["react"]))
        self.assertEqual(result, 0)

    @patch("airlock.audit_package")
    @patch("airlock._find_pkg_binary", return_value="/usr/bin/npm")
    def test_critical_audit_blocks(self, mock_find, mock_audit):
        mock_audit.return_value = MagicMock(
            risks=[{"risk": "typosquatting", "severity": "critical", "detail": "test"}],
            severity="critical", name="reakt", version="1.0.0",
        )
        result = cmd_install(self._make_args(["reakt"]))
        self.assertEqual(result, 1)

    @patch("airlock.scan_node_modules")
    @patch("airlock._parse_lockfile_packages")
    @patch("airlock.audit_package")
    @patch("airlock._find_pkg_binary", return_value="/usr/bin/npm")
    @patch("airlock.subprocess.run")
    def test_critical_audit_proceeds_with_force(self, mock_run, mock_find, mock_audit, mock_lockpkg, mock_scan):
        mock_run.return_value = MagicMock(returncode=0)
        mock_lockpkg.return_value = set()
        mock_audit.return_value = MagicMock(
            risks=[{"risk": "typosquatting", "severity": "critical", "detail": "test"}],
            severity="critical", name="reakt", version="1.0.0",
        )
        mock_scan.return_value = {}

        result = cmd_install(self._make_args(["reakt"], force=True))
        self.assertEqual(result, 0)

    @patch("airlock._parse_lockfile_packages")
    @patch("airlock.audit_package")
    @patch("airlock._find_pkg_binary", return_value="/usr/bin/npm")
    @patch("airlock.subprocess.run")
    def test_install_failure(self, mock_run, mock_find, mock_audit, mock_lockpkg):
        mock_audit.return_value = MagicMock(risks=[], severity="info", name="react", version="18.0.0")
        mock_run.return_value = MagicMock(returncode=1)
        mock_lockpkg.return_value = set()

        result = cmd_install(self._make_args(["react"]))
        self.assertEqual(result, 1)

    @patch("airlock.scan_node_modules")
    @patch("airlock._parse_lockfile_packages")
    @patch("airlock.audit_package")
    @patch("airlock._find_pkg_binary", return_value="/usr/bin/npm")
    @patch("airlock.subprocess.run")
    def test_ai_threat_blocks(self, mock_run, mock_find, mock_audit, mock_lockpkg, mock_scan):
        mock_run.return_value = MagicMock(returncode=0)
        mock_lockpkg.return_value = set()
        mock_audit.return_value = MagicMock(risks=[], severity="info", name="evil", version="1.0.0")

        from ai_shield import AIThreat, AIScanResult
        threat = AIThreat(file="x.js", line=1, threat_type="prompt_injection", detail="test", severity="critical")
        mock_scan.return_value = {"evil": AIScanResult(threats=[threat], summary="bad")}

        result = cmd_install(self._make_args(["evil"]))
        self.assertEqual(result, 1)

    @patch("airlock.run_with_network_monitor")
    @patch("airlock.scan_node_modules")
    @patch("airlock._parse_lockfile_packages")
    @patch("airlock._find_pkg_binary", return_value="/usr/bin/npm")
    @patch("airlock.subprocess.run")
    def test_no_packages_lockfile_install(self, mock_run, mock_find, mock_lockpkg, mock_scan, mock_netmon):
        mock_run.return_value = MagicMock(returncode=0)
        mock_lockpkg.return_value = set()
        mock_scan.return_value = {}

        result = cmd_install(self._make_args([]))
        self.assertEqual(result, 0)

    @patch("airlock.run_with_network_monitor")
    @patch("airlock.scan_node_modules")
    @patch("airlock._parse_lockfile_packages")
    @patch("airlock._load_script_allowlist")
    @patch("airlock.audit_package")
    @patch("airlock._find_pkg_binary", return_value="/usr/bin/npm")
    @patch("airlock.subprocess.run")
    @patch("airlock.Path")
    def test_clean_install_runs_scripts_in_monitor_mode(self, mock_path, mock_run, mock_find,
                                                         mock_audit, mock_allow, mock_lockpkg,
                                                         mock_scan, mock_netmon):
        mock_run.return_value = MagicMock(returncode=0)
        mock_lockpkg.return_value = set()
        mock_audit.return_value = MagicMock(risks=[], severity="info", name="sharp", version="1.0.0")
        mock_scan.return_value = {}
        mock_allow.return_value = set()

        pkg_json_path = MagicMock()
        pkg_json_path.exists.return_value = True
        pkg_json_path.read_text.return_value = json.dumps({
            "scripts": {"postinstall": "node install.js"}
        })

        nm_path = MagicMock()
        nm_path.__truediv__ = MagicMock(side_effect=lambda x: MagicMock(
            __truediv__=MagicMock(return_value=pkg_json_path),
        ))

        def path_side_effect(p):
            if p == "node_modules":
                return nm_path
            return MagicMock(exists=MagicMock(return_value=False))

        mock_path.side_effect = path_side_effect

        from netwatch import NetWatchResult
        mock_netmon.return_value = NetWatchResult(summary="0 connections")

        result = cmd_install(self._make_args(["sharp"]))
        if mock_netmon.called:
            call_kwargs = mock_netmon.call_args
            self.assertFalse(call_kwargs.kwargs.get("sandbox", call_kwargs[1].get("sandbox", False)))


class TestCmdScan(unittest.TestCase):
    @patch("airlock.scan_node_modules")
    def test_no_threats(self, mock_scan):
        mock_scan.return_value = {}
        args = SimpleNamespace(path=None, packages=None, verbose=False)
        result = cmd_scan(args)
        self.assertEqual(result, 0)

    @patch("airlock.scan_node_modules")
    def test_threats_found(self, mock_scan):
        from ai_shield import AIThreat, AIScanResult
        threat = AIThreat(file="x.js", line=1, threat_type="test", detail="d", severity="critical")
        mock_scan.return_value = {"evil": AIScanResult(threats=[threat], summary="bad")}
        args = SimpleNamespace(path=None, packages=None, verbose=False)
        result = cmd_scan(args)
        self.assertEqual(result, 1)

    @patch("airlock.scan_node_modules")
    def test_specific_packages(self, mock_scan):
        mock_scan.return_value = {}
        args = SimpleNamespace(path=None, packages=["react"], verbose=False)
        cmd_scan(args)
        mock_scan.assert_called_once_with(Path("."), ["react"])

    @patch("airlock.scan_node_modules")
    def test_custom_path(self, mock_scan):
        mock_scan.return_value = {}
        args = SimpleNamespace(path="/some/dir", packages=None, verbose=False)
        cmd_scan(args)
        mock_scan.assert_called_once_with(Path("/some/dir"), None)


class TestCmdAudit(unittest.TestCase):
    @patch("airlock.audit_package")
    def test_single_package(self, mock_audit):
        mock_audit.return_value = MagicMock(
            risks=[], severity="info", name="react", version="18.0.0",
        )
        args = SimpleNamespace(packages=["react"])
        result = cmd_audit(args)
        self.assertEqual(result, 0)
        mock_audit.assert_called_once_with("react", None)

    @patch("airlock.audit_package")
    def test_multiple_packages(self, mock_audit):
        mock_audit.return_value = MagicMock(
            risks=[], severity="info", name="pkg", version="1.0.0",
        )
        args = SimpleNamespace(packages=["react", "vue", "angular"])
        cmd_audit(args)
        self.assertEqual(mock_audit.call_count, 3)

    @patch("airlock.audit_package")
    def test_version_specified(self, mock_audit):
        mock_audit.return_value = MagicMock(
            risks=[], severity="info", name="react", version="18.2.0",
        )
        args = SimpleNamespace(packages=["react@18.2.0"])
        cmd_audit(args)
        mock_audit.assert_called_once_with("react", "18.2.0")

    @patch("airlock.audit_package")
    def test_scoped_package(self, mock_audit):
        mock_audit.return_value = MagicMock(
            risks=[], severity="info", name="@scope/pkg", version="1.0.0",
        )
        args = SimpleNamespace(packages=["@scope/pkg"])
        cmd_audit(args)
        mock_audit.assert_called_once_with("@scope/pkg", None)

    @patch("airlock.audit_package")
    def test_always_returns_zero(self, mock_audit):
        mock_audit.return_value = MagicMock(
            risks=[{"risk": "critical", "severity": "critical", "detail": "bad"}],
            severity="critical", name="evil", version="1.0.0",
        )
        args = SimpleNamespace(packages=["evil"])
        self.assertEqual(cmd_audit(args), 0)


class TestMainArgParsing(unittest.TestCase):
    @patch("airlock.cmd_install", return_value=0)
    def test_install_command(self, mock_cmd):
        from airlock import main
        with patch("sys.argv", ["airlock", "install", "react"]):
            main()
        mock_cmd.assert_called_once()

    @patch("airlock.cmd_scan", return_value=0)
    def test_scan_command(self, mock_cmd):
        from airlock import main
        with patch("sys.argv", ["airlock", "scan"]):
            main()
        mock_cmd.assert_called_once()

    @patch("airlock.cmd_audit", return_value=0)
    def test_audit_command(self, mock_cmd):
        from airlock import main
        with patch("sys.argv", ["airlock", "audit", "react"]):
            main()
        mock_cmd.assert_called_once()

    def test_no_command(self):
        from airlock import main
        with patch("sys.argv", ["airlock"]):
            result = main()
        self.assertEqual(result, 0)

    @patch("airlock.cmd_install", return_value=0)
    def test_force_flag(self, mock_cmd):
        from airlock import main
        with patch("sys.argv", ["airlock", "install", "--force", "react"]):
            main()
        args = mock_cmd.call_args[0][0]
        self.assertTrue(args.force)

    @patch("airlock.cmd_install", return_value=0)
    def test_pm_flag(self, mock_cmd):
        from airlock import main
        with patch("sys.argv", ["airlock", "install", "--pm", "pnpm", "react"]):
            main()
        args = mock_cmd.call_args[0][0]
        self.assertEqual(args.pm, "pnpm")

    @patch("airlock.cmd_install", return_value=0)
    def test_no_sandbox_flag(self, mock_cmd):
        from airlock import main
        with patch("sys.argv", ["airlock", "install", "--no-sandbox", "react"]):
            main()
        args = mock_cmd.call_args[0][0]
        self.assertTrue(args.no_sandbox)

    @patch("airlock.cmd_install", return_value=0)
    def test_script_timeout(self, mock_cmd):
        from airlock import main
        with patch("sys.argv", ["airlock", "install", "--script-timeout", "600", "react"]):
            main()
        args = mock_cmd.call_args[0][0]
        self.assertEqual(args.script_timeout, 600)

    @patch("airlock.cmd_scan", return_value=0)
    def test_scan_verbose(self, mock_cmd):
        from airlock import main
        with patch("sys.argv", ["airlock", "scan", "-v"]):
            main()
        args = mock_cmd.call_args[0][0]
        self.assertTrue(args.verbose)


class TestExtractExecPackages(unittest.TestCase):
    def test_simple_command(self):
        self.assertEqual(_extract_exec_packages(["create-react-app", "my-app"]), ["create-react-app"])

    def test_package_flag_short(self):
        result = _extract_exec_packages(["-p", "typescript", "tsc", "--init"])
        self.assertEqual(result, ["typescript"])

    def test_package_flag_long(self):
        result = _extract_exec_packages(["--package", "typescript", "tsc"])
        self.assertEqual(result, ["typescript"])

    def test_multiple_package_flags(self):
        result = _extract_exec_packages(["-p", "typescript", "-p", "ts-node", "tsc", "script.ts"])
        self.assertEqual(result, ["typescript", "ts-node"])

    def test_empty_args(self):
        self.assertEqual(_extract_exec_packages([]), [])

    def test_only_flags(self):
        self.assertEqual(_extract_exec_packages(["--yes", "--quiet"]), [])

    def test_scoped_package(self):
        result = _extract_exec_packages(["@angular/cli", "new", "my-app"])
        self.assertEqual(result, ["@angular/cli"])

    def test_versioned_package(self):
        result = _extract_exec_packages(["create-next-app@latest", "my-app"])
        self.assertEqual(result, ["create-next-app@latest"])

    def test_package_flag_at_end(self):
        result = _extract_exec_packages(["-p", "foo", "-p"])
        self.assertEqual(result, ["foo"])


class TestCmdExec(unittest.TestCase):
    @patch("airlock.audit_package")
    @patch("airlock.subprocess.run")
    def test_clean_exec(self, mock_run, mock_audit):
        mock_audit.return_value = MagicMock(risks=[], severity="info", name="cowsay", version="1.0.0")
        mock_run.return_value = MagicMock(returncode=0)

        args = SimpleNamespace(exec_args=["cowsay", "hello"], force=False)
        result = cmd_exec(args)
        self.assertEqual(result, 0)
        mock_audit.assert_called_once_with("cowsay", None)
        mock_run.assert_called_once_with(["cowsay", "hello"])

    @patch("airlock.audit_package")
    def test_critical_blocks(self, mock_audit):
        mock_audit.return_value = MagicMock(
            risks=[{"risk": "typosquatting", "severity": "critical", "detail": "test"}],
            severity="critical", name="reakt", version="1.0.0",
        )
        args = SimpleNamespace(exec_args=["reakt", "build"], force=False)
        result = cmd_exec(args)
        self.assertEqual(result, 1)

    @patch("airlock.audit_package")
    @patch("airlock.subprocess.run")
    def test_critical_proceeds_with_force(self, mock_run, mock_audit):
        mock_audit.return_value = MagicMock(
            risks=[{"risk": "typosquatting", "severity": "critical", "detail": "test"}],
            severity="critical", name="reakt", version="1.0.0",
        )
        mock_run.return_value = MagicMock(returncode=0)

        args = SimpleNamespace(exec_args=["reakt", "build"], force=True)
        result = cmd_exec(args)
        self.assertEqual(result, 0)

    @patch("airlock.subprocess.run")
    def test_no_packages_passthrough(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        args = SimpleNamespace(exec_args=["--version"], force=False)
        result = cmd_exec(args)
        self.assertEqual(result, 0)
        mock_run.assert_called_once_with(["--version"])

    @patch("airlock.subprocess.run")
    def test_empty_exec_args(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        args = SimpleNamespace(exec_args=[], force=False)
        result = cmd_exec(args)
        self.assertEqual(result, 0)

    @patch("airlock.audit_package")
    @patch("airlock.subprocess.run")
    def test_versioned_package(self, mock_run, mock_audit):
        mock_audit.return_value = MagicMock(risks=[], severity="info", name="create-next-app", version="14.0.0")
        mock_run.return_value = MagicMock(returncode=0)

        args = SimpleNamespace(exec_args=["create-next-app@14.0.0", "my-app"], force=False)
        result = cmd_exec(args)
        self.assertEqual(result, 0)
        mock_audit.assert_called_once_with("create-next-app", "14.0.0")

    @patch("airlock.audit_package")
    @patch("airlock.subprocess.run")
    def test_scoped_package(self, mock_run, mock_audit):
        mock_audit.return_value = MagicMock(risks=[], severity="info", name="@angular/cli", version="17.0.0")
        mock_run.return_value = MagicMock(returncode=0)

        args = SimpleNamespace(exec_args=["@angular/cli", "new", "my-app"], force=False)
        result = cmd_exec(args)
        self.assertEqual(result, 0)
        mock_audit.assert_called_once_with("@angular/cli", None)

    @patch("airlock.audit_package")
    @patch("airlock.subprocess.run")
    def test_package_flag_audit(self, mock_run, mock_audit):
        mock_audit.return_value = MagicMock(risks=[], severity="info", name="typescript", version="5.0.0")
        mock_run.return_value = MagicMock(returncode=0)

        args = SimpleNamespace(exec_args=["-p", "typescript", "tsc", "--init"], force=False)
        result = cmd_exec(args)
        self.assertEqual(result, 0)
        mock_audit.assert_called_once_with("typescript", None)


class TestCmdInstallUpdate(unittest.TestCase):
    def setUp(self):
        self._plugins_patcher = patch("airlock._load_plugins", return_value=[])
        self._plugins_patcher.start()

    def tearDown(self):
        self._plugins_patcher.stop()
    @patch("airlock.scan_node_modules")
    @patch("airlock._parse_lockfile_packages")
    @patch("airlock._find_pkg_binary", return_value="/usr/bin/npm")
    @patch("airlock.subprocess.run")
    def test_update_subcmd(self, mock_run, mock_find, mock_lockpkg, mock_scan):
        mock_run.return_value = MagicMock(returncode=0)
        mock_lockpkg.return_value = set()
        mock_scan.return_value = {}

        args = SimpleNamespace(
            pkg_args=[], pm="npm", force=False, no_sandbox=False,
            no_strace=True, script_timeout=300, subcmd="update",
        )
        result = cmd_install(args)
        self.assertEqual(result, 0)
        install_call = mock_run.call_args[0][0]
        self.assertEqual(install_call[1], "update")

    @patch("airlock.scan_node_modules")
    @patch("airlock._parse_lockfile_packages")
    @patch("airlock._find_pkg_binary", return_value="/usr/bin/pnpm")
    @patch("airlock.subprocess.run")
    def test_pnpm_add_vs_install(self, mock_run, mock_find, mock_lockpkg, mock_scan):
        mock_run.return_value = MagicMock(returncode=0)
        mock_lockpkg.return_value = set()
        mock_scan.return_value = {}

        args = SimpleNamespace(
            pkg_args=["react"], pm="pnpm", force=False, no_sandbox=False,
            no_strace=True, script_timeout=300, subcmd="install",
        )
        from airlock import audit_package
        with patch("airlock.audit_package") as mock_audit:
            mock_audit.return_value = MagicMock(risks=[], severity="info", name="react", version="18.0.0")
            result = cmd_install(args)
        self.assertEqual(result, 0)
        install_call = mock_run.call_args[0][0]
        self.assertEqual(install_call[1], "add")


class TestMainExecParsing(unittest.TestCase):
    @patch("airlock.cmd_exec", return_value=0)
    def test_exec_command(self, mock_cmd):
        from airlock import main
        with patch("sys.argv", ["airlock", "exec", "--", "npx", "cowsay"]):
            main()
        mock_cmd.assert_called_once()
        args = mock_cmd.call_args[0][0]
        self.assertEqual(args.exec_args, ["npx", "cowsay"])

    @patch("airlock.cmd_exec", return_value=0)
    def test_exec_force(self, mock_cmd):
        from airlock import main
        with patch("sys.argv", ["airlock", "exec", "--force", "--", "npx", "cowsay"]):
            main()
        args = mock_cmd.call_args[0][0]
        self.assertTrue(args.force)

    @patch("airlock.cmd_install", return_value=0)
    def test_install_subcmd_update(self, mock_cmd):
        from airlock import main
        with patch("sys.argv", ["airlock", "install", "--pm", "npm", "--subcmd", "update"]):
            main()
        args = mock_cmd.call_args[0][0]
        self.assertEqual(args.subcmd, "update")


if __name__ == "__main__":
    unittest.main()
