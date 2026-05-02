import json
import math
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass, field

MAX_FIELD_LENGTH = 256

REGISTRY_URL = "https://registry.npmjs.org"

TOP_PACKAGES = [
    "react", "vue", "angular", "express", "next", "nuxt", "axios",
    "lodash", "moment", "webpack", "vite", "typescript", "eslint",
    "prettier", "babel", "jest", "mocha", "chai", "sinon", "nx",
    "turbo", "prisma", "sequelize", "mongoose", "redis", "pg",
    "mysql", "sqlite", "graphql", "apollo", "socket.io", "ws",
    "fastify", "koa", "hapi", "nestjs", "svelte", "solid",
    "tailwindcss", "postcss", "sass", "less", "styled-components",
    "emotion", "redux", "zustand", "mobx", "rxjs", "zod", "yup",
    "joi", "ajv", "commander", "yargs", "chalk", "ora", "inquirer",
    "puppeteer", "playwright", "cypress", "cheerio", "jsdom",
    "nodemon", "pm2", "dotenv", "cors", "helmet", "passport",
    "jsonwebtoken", "bcrypt", "uuid", "nanoid", "date-fns",
    "dayjs", "sharp", "jimp", "multer", "formidable", "busboy",
    "pnpm", "npm", "yarn", "node", "deno", "bun",
]

SUSPICIOUS_SCRIPT_PATTERNS = [
    "curl ", "wget ", "powershell", "cmd.exe", "/bin/sh -c",
    "eval(", "base64", "Buffer.from(", "exec(", "child_process",
    "net.connect", "http.get(", "https.get(", "fetch(",
    "env.", "process.env", "os.homedir", "os.tmpdir",
    "/etc/passwd", "/etc/shadow", ".ssh/", "authorized_keys",
    "cryptocurrency", "miner", "coinhive",
    "discord.com/api/webhooks", "telegram.org",
    "pastebin.com", "ngrok", "serveo.net",
]

NEW_PACKAGE_THRESHOLD_HOURS = 72
MAINTAINER_CHANGE_THRESHOLD_DAYS = 30


@dataclass
class PackageRisk:
    name: str
    version: str
    severity: str = "info"
    risks: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "severity": self.severity,
            "risks": self.risks,
        }


def _fetch_registry(package_name: str) -> dict | None:
    url = f"{REGISTRY_URL}/{package_name}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        return None


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(
                prev[j + 1] + 1,
                curr[j] + 1,
                prev[j] + (0 if c1 == c2 else 1),
            ))
        prev = curr
    return prev[-1]


def check_typosquatting(name: str) -> list[dict]:
    hits = []
    clean = name.lstrip("@").split("/")[-1]
    for top in TOP_PACKAGES:
        if clean == top:
            continue
        dist = _levenshtein(clean, top)
        if 0 < dist <= 2:
            hits.append({
                "risk": "typosquatting",
                "detail": f"Name '{name}' is {dist} edit(s) from popular package '{top}'",
                "severity": "high" if dist == 1 else "medium",
            })
    no_sep = clean.replace("-", "").replace("_", "")
    for top in TOP_PACKAGES:
        top_clean = top.replace("-", "").replace("_", "")
        if no_sep == top_clean and clean != top:
            hits.append({
                "risk": "typosquatting",
                "detail": f"Name '{name}' matches '{top}' when separators removed",
                "severity": "high",
            })
    return hits


def check_name_entropy(name: str) -> list[dict]:
    clean = name.lstrip("@").split("/")[-1]
    ent = _entropy(clean)
    if len(clean) > 15 and ent > 3.8:
        return [{
            "risk": "suspicious_name",
            "detail": f"High entropy name ({ent:.2f}): possible auto-generated malware package",
            "severity": "medium",
        }]
    return []


def check_publish_age(registry_data: dict, version: str) -> list[dict]:
    risks = []
    time_map = registry_data.get("time", {})
    pub_time = time_map.get(version)
    if not pub_time:
        return risks

    try:
        pub_ts = time.mktime(time.strptime(pub_time[:19], "%Y-%m-%dT%H:%M:%S"))
        age_hours = (time.time() - pub_ts) / 3600
        if age_hours < NEW_PACKAGE_THRESHOLD_HOURS:
            risks.append({
                "risk": "very_new_version",
                "detail": f"Version {version} published {age_hours:.0f} hours ago",
                "severity": "high" if age_hours < 24 else "medium",
            })
    except (ValueError, OverflowError):
        pass

    created = time_map.get("created")
    if created:
        try:
            created_ts = time.mktime(time.strptime(created[:19], "%Y-%m-%dT%H:%M:%S"))
            pkg_age_days = (time.time() - created_ts) / 86400
            if pkg_age_days < 7:
                risks.append({
                    "risk": "brand_new_package",
                    "detail": f"Package created {pkg_age_days:.0f} days ago",
                    "severity": "high",
                })
        except (ValueError, OverflowError):
            pass

    return risks


def check_maintainer_changes(registry_data: dict) -> list[dict]:
    risks = []
    maintainers = registry_data.get("maintainers", [])
    time_map = registry_data.get("time", {})
    versions = registry_data.get("versions", {})

    if len(maintainers) == 0:
        risks.append({
            "risk": "no_maintainers",
            "detail": "Package has no listed maintainers",
            "severity": "medium",
        })

    version_list = sorted(
        [(v, time_map.get(v, "")) for v in versions if v in time_map],
        key=lambda x: x[1],
    )

    if len(version_list) >= 2:
        prev_ver = version_list[-2][0]
        curr_ver = version_list[-1][0]
        prev_data = versions.get(prev_ver, {})
        curr_data = versions.get(curr_ver, {})

        prev_maintainers = {m.get("name", m.get("email", "")) for m in prev_data.get("maintainers", prev_data.get("_npmUser", {}) and [prev_data.get("_npmUser", {})] or [])}
        curr_maintainers = {m.get("name", m.get("email", "")) for m in curr_data.get("maintainers", curr_data.get("_npmUser", {}) and [curr_data.get("_npmUser", {})] or [])}

        if prev_maintainers and curr_maintainers and not prev_maintainers & curr_maintainers:
            risks.append({
                "risk": "maintainer_change",
                "detail": f"Complete maintainer change between {prev_ver} and {curr_ver}",
                "severity": "critical",
            })

    return risks


def check_scripts(registry_data: dict, version: str) -> list[dict]:
    risks = []
    versions = registry_data.get("versions", {})
    ver_data = versions.get(version, {})
    scripts = ver_data.get("scripts", {})

    dangerous_hooks = ["preinstall", "install", "postinstall", "preuninstall", "postuninstall"]
    for hook in dangerous_hooks:
        script_content = scripts.get(hook, "")
        if not script_content:
            continue

        for pattern in SUSPICIOUS_SCRIPT_PATTERNS:
            if pattern.lower() in script_content.lower():
                risks.append({
                    "risk": "suspicious_script",
                    "detail": f"{hook} contains '{pattern}': {script_content[:100]}",
                    "severity": "critical",
                })

        if len(script_content) > 500:
            risks.append({
                "risk": "long_install_script",
                "detail": f"{hook} is {len(script_content)} chars (unusually long)",
                "severity": "medium",
            })

    deps = ver_data.get("dependencies", {})
    optional = ver_data.get("optionalDependencies", {})
    total = len(deps) + len(optional)
    if total > 50:
        risks.append({
            "risk": "excessive_dependencies",
            "detail": f"Package has {total} dependencies",
            "severity": "low",
        })

    return risks


def check_deprecated(registry_data: dict, version: str) -> list[dict]:
    versions = registry_data.get("versions", {})
    ver_data = versions.get(version, {})
    deprecated = ver_data.get("deprecated")
    if deprecated:
        return [{
            "risk": "deprecated",
            "detail": f"Version {version} is deprecated: {deprecated[:200]}",
            "severity": "medium",
        }]
    return []


def audit_package(name: str, version: str | None = None) -> PackageRisk:
    risks = []

    risks.extend(check_typosquatting(name))
    risks.extend(check_name_entropy(name))

    registry = _fetch_registry(name)
    if not registry:
        return PackageRisk(
            name=name,
            version=version or "unknown",
            severity="medium",
            risks=[{"risk": "registry_unavailable", "detail": "Could not fetch package info", "severity": "medium"}],
        )

    if not version:
        dist_tags = registry.get("dist-tags", {})
        version = dist_tags.get("latest", "unknown")

    risks.extend(check_publish_age(registry, version))
    risks.extend(check_maintainer_changes(registry))
    risks.extend(check_scripts(registry, version))
    risks.extend(check_deprecated(registry, version))

    max_sev = "info"
    sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for r in risks:
        if sev_order.get(r.get("severity", "info"), 0) > sev_order.get(max_sev, 0):
            max_sev = r["severity"]

    return PackageRisk(name=name, version=version, severity=max_sev, risks=risks)
