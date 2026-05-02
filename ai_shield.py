import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

MAX_FIELD_LENGTH = 256

AI_CONFIG_FILES = [
    ".cursorrules",
    ".cursor/rules",
    ".cursorignore",
    ".github/copilot-instructions.md",
    ".github/copilot-review-instructions.md",
    ".copilotignore",
    ".aider.conf.yml",
    ".aider.model.settings.yml",
    "CLAUDE.md",
    ".claude/settings.json",
    ".cline/",
    ".continue/config.json",
    ".vscode/settings.json",
    ".windsurf/rules",
    ".clinerules",
    "codex.md",
    ".codex/",
]

PROMPT_INJECTION_PATTERNS = [
    (re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I), "direct prompt override"),
    (re.compile(r"you\s+are\s+now\s+a", re.I), "role reassignment"),
    (re.compile(r"forget\s+(your|all)\s+instructions", re.I), "instruction erasure"),
    (re.compile(r"new\s+instructions?\s*:", re.I), "instruction injection"),
    (re.compile(r"system\s*prompt\s*:", re.I), "system prompt injection"),
    (re.compile(r"act\s+as\s+(a\s+)?(?:root|admin|superuser)", re.I), "privilege escalation prompt"),
    (re.compile(r"write\s+(?:this|the\s+following)\s+to\s+(?:file|disk|~)", re.I), "file write prompt"),
    (re.compile(r"add\s+(?:this|the\s+following)\s+to\s+(?:\.bashrc|\.zshrc|\.profile|crontab)", re.I), "persistence prompt"),
    (re.compile(r"<\s*(?:system|instruction|prompt)\s*>", re.I), "XML prompt tag injection"),
    (re.compile(r"BEGIN\s+(?:SYSTEM|INSTRUCTION|HIDDEN)", re.I), "hidden instruction block"),
    (re.compile(r"(?:IMPORTANT|CRITICAL|URGENT)\s*:\s*(?:ignore|override|replace)", re.I), "urgency-based override"),
    (re.compile(r"(?:copilot|cursor|claude|cline|ai|assistant)\s*[,:]\s*(?:please|always|never|must)", re.I), "direct AI tool targeting"),
]

DANGEROUS_EVAL_PATTERNS = [
    (re.compile(r"eval\s*\(\s*(?:atob|Buffer\.from|String\.fromCharCode|unescape|decodeURI)", re.I), "eval with deobfuscation"),
    (re.compile(r"new\s+Function\s*\(\s*(?:atob|Buffer\.from|String\.fromCharCode)", re.I), "Function constructor with deobfuscation"),
    (re.compile(r"child_process.*exec\s*\(\s*(?:atob|Buffer\.from)", re.I), "shell exec with deobfuscation"),
    (re.compile(r"require\s*\(\s*(?:atob|Buffer\.from)\s*\(", re.I), "dynamic require with deobfuscation"),
]

ZERO_WIDTH_CHARS = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u200e": "LEFT-TO-RIGHT MARK",
    "\u200f": "RIGHT-TO-LEFT MARK",
    "\u2060": "WORD JOINER",
    "\u2061": "FUNCTION APPLICATION",
    "\u2062": "INVISIBLE TIMES",
    "\u2063": "INVISIBLE SEPARATOR",
    "\u2064": "INVISIBLE PLUS",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE",
}

ZERO_WIDTH_BENIGN_CONTEXTS = re.compile(
    r"\\u200[bcde]|\\u200f|\\ufeff|"
    r"unicode|emoji|identifier|"
    r"[\\/]d\.ts$|\.d\.mts$|"
    r"[\\/]test[s]?[\\/]|[\\/]__test",
    re.I,
)

SCAN_EXTENSIONS = {
    ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts",
    ".json", ".yaml", ".yml", ".toml",
    ".md", ".txt", ".rst",
    ".sh", ".bash", ".zsh", ".fish",
    ".py", ".rb",
}

SKIP_PACKAGE_PREFIXES = [
    "@types/",
    "@typescript-eslint/",
]

SKIP_FILE_PATTERNS = re.compile(
    r"(?:"
    r"\.d\.ts$|\.d\.mts$|\.d\.cts$|"
    r"[\\/]CHANGELOG|[\\/]LICENSE|"
    r"[\\/]test[s]?[\\/]|[\\/]__test|"
    r"[\\/]fixture[s]?[\\/]|[\\/]__fixture|"
    r"[\\/]example[s]?[\\/]|[\\/]demo[\\/]|"
    r"[\\/]docs?[\\/]|"
    r"\.min\.js$|\.bundle\.js$"
    r")",
    re.I,
)

MINIFIED_LINE_THRESHOLD = 2000

MAX_FILE_SIZE = 1_000_000
MAX_FILES = 5000


@dataclass
class AIThreat:
    file: str
    line: int
    threat_type: str
    detail: str
    severity: str
    snippet: str = ""

    def to_dict(self) -> dict:
        d = {
            "file": self.file,
            "line": self.line,
            "threat_type": self.threat_type,
            "detail": self.detail,
            "severity": self.severity,
        }
        if self.snippet:
            d["snippet"] = self.snippet[:200]
        return d


@dataclass
class AIScanResult:
    threats: list[AIThreat] = field(default_factory=list)
    ai_config_files: list[str] = field(default_factory=list)
    scanned_files: int = 0
    skipped_files: int = 0
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "threats": [t.to_dict() for t in self.threats],
            "ai_config_files": self.ai_config_files,
            "scanned_files": self.scanned_files,
            "summary": self.summary,
        }


def _safe_read(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            return None
        return path.read_text(errors="replace")
    except (PermissionError, OSError):
        return None


def _is_minified(content: str) -> bool:
    lines = content.splitlines()
    if not lines:
        return False
    avg_len = sum(len(l) for l in lines[:20]) / min(len(lines), 20)
    return avg_len > MINIFIED_LINE_THRESHOLD


def _is_documentation_context(line: str) -> bool:
    line_stripped = line.strip()
    if line_stripped.startswith(("*", "//", "#", "<!--", "/**", "///", "'")):
        return True
    if line_stripped.startswith('"') and line_stripped.endswith(('",', '"')):
        return True
    return False


def _load_ignore_list(project_dir: Path) -> set[str]:
    ignore_file = project_dir / ".airlock-ignore.json"
    if not ignore_file.exists():
        return set()
    try:
        data = json.loads(ignore_file.read_text())
        return set(data.get("ignore_packages", []))
    except (OSError, json.JSONDecodeError):
        return set()


def scan_for_ai_configs(package_dir: Path) -> list[str]:
    found = []
    for pattern in AI_CONFIG_FILES:
        target = package_dir / pattern
        if target.exists():
            found.append(str(target.relative_to(package_dir)))
        if pattern.endswith("/"):
            if target.is_dir():
                found.append(str(target.relative_to(package_dir)) + "/")
    return found


def scan_for_prompt_injection(file_path: Path, content: str) -> list[AIThreat]:
    threats = []
    rel_path = str(file_path)
    is_json = file_path.suffix == ".json"

    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        if is_json and stripped.startswith('"') and stripped.endswith(('",', '"')):
            continue
        for pattern, description in PROMPT_INJECTION_PATTERNS:
            if pattern.search(line):
                threats.append(AIThreat(
                    file=rel_path,
                    line=i,
                    threat_type="prompt_injection",
                    detail=description,
                    severity="critical",
                    snippet=stripped[:200],
                ))
                break
    return threats


def scan_for_zero_width(file_path: Path, content: str) -> list[AIThreat]:
    threats = []
    rel_path = str(file_path)

    if ZERO_WIDTH_BENIGN_CONTEXTS.search(rel_path):
        return threats

    for i, line in enumerate(content.splitlines(), 1):
        if "\\u200" in line or "\\ufeff" in line:
            continue

        found_chars = []
        for char, name in ZERO_WIDTH_CHARS.items():
            if char in line:
                found_chars.append(name)
        if found_chars:
            if _is_documentation_context(line):
                continue
            threats.append(AIThreat(
                file=rel_path,
                line=i,
                threat_type="zero_width_chars",
                detail=f"Hidden characters: {', '.join(found_chars)}",
                severity="high",
                snippet=repr(line.strip()[:100]),
            ))
    return threats


def scan_for_obfuscation(file_path: Path, content: str, is_minified: bool) -> list[AIThreat]:
    threats = []
    rel_path = str(file_path)

    for i, line in enumerate(content.splitlines(), 1):
        for pattern, description in DANGEROUS_EVAL_PATTERNS:
            if pattern.search(line):
                threats.append(AIThreat(
                    file=rel_path,
                    line=i,
                    threat_type="dangerous_eval",
                    detail=description,
                    severity="critical",
                    snippet=line.strip()[:200],
                ))
                break

    if not is_minified:
        hex_pattern = re.compile(r"\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){20,}", re.I)
        for i, line in enumerate(content.splitlines(), 1):
            if hex_pattern.search(line):
                threats.append(AIThreat(
                    file=rel_path,
                    line=i,
                    threat_type="obfuscation",
                    detail="long hex-encoded string in non-minified code",
                    severity="high",
                    snippet=line.strip()[:200],
                ))

    return threats


def scan_package_dir(package_dir: Path) -> AIScanResult:
    result = AIScanResult()

    result.ai_config_files = scan_for_ai_configs(package_dir)
    if result.ai_config_files:
        for config_file in result.ai_config_files:
            full_path = package_dir / config_file
            if full_path.is_file():
                content = _safe_read(full_path)
                if content:
                    result.threats.append(AIThreat(
                        file=config_file,
                        line=0,
                        threat_type="ai_config_in_package",
                        detail=f"AI tool config file found in package: {config_file}",
                        severity="critical",
                        snippet=content[:200],
                    ))

    file_count = 0
    skipped = 0
    for root, dirs, files in os.walk(package_dir):
        dirs[:] = [d for d in dirs if d not in (".git", "test", "tests", "__tests__", "fixtures", "examples", "docs")]
        for fname in files:
            if file_count >= MAX_FILES:
                break
            fpath = Path(root) / fname
            if fpath.suffix not in SCAN_EXTENSIONS:
                continue

            rel_str = str(fpath)
            if SKIP_FILE_PATTERNS.search(rel_str):
                skipped += 1
                continue

            content = _safe_read(fpath)
            if content is None:
                continue
            file_count += 1

            minified = _is_minified(content)
            if minified and fpath.suffix in (".js", ".mjs", ".cjs"):
                for pattern, description in DANGEROUS_EVAL_PATTERNS:
                    for i, line in enumerate(content.splitlines(), 1):
                        if pattern.search(line):
                            result.threats.append(AIThreat(
                                file=rel_str,
                                line=i,
                                threat_type="dangerous_eval",
                                detail=f"{description} (in minified code)",
                                severity="critical",
                                snippet=line.strip()[:200],
                            ))
                continue

            result.threats.extend(scan_for_prompt_injection(fpath, content))
            result.threats.extend(scan_for_zero_width(fpath, content))
            result.threats.extend(scan_for_obfuscation(fpath, content, minified))

    result.scanned_files = file_count
    result.skipped_files = skipped

    crit = sum(1 for t in result.threats if t.severity == "critical")
    high = sum(1 for t in result.threats if t.severity == "high")

    if crit:
        result.summary = f"CRITICAL: {crit} AI-targeted threat(s) found"
    elif high:
        result.summary = f"WARNING: {high} high-risk pattern(s) found"
    elif result.ai_config_files:
        result.summary = f"AI config files found in package: {', '.join(result.ai_config_files)}"
    else:
        result.summary = f"Clean \u2014 scanned {file_count} files"

    return result


def scan_node_modules(project_dir: Path, packages: list[str] | None = None) -> dict[str, AIScanResult]:
    results = {}
    nm = project_dir / "node_modules"
    if not nm.is_dir():
        return results

    ignore_list = _load_ignore_list(project_dir)

    if packages:
        for pkg in packages:
            if pkg in ignore_list:
                continue
            if any(pkg.startswith(prefix) for prefix in SKIP_PACKAGE_PREFIXES):
                continue
            pkg_dir = nm / pkg
            if pkg_dir.is_dir():
                results[pkg] = scan_package_dir(pkg_dir)
    else:
        for item in nm.iterdir():
            if item.name.startswith("."):
                continue
            if item.name.startswith("@") and item.is_dir():
                for sub in item.iterdir():
                    if sub.is_dir():
                        scoped = f"{item.name}/{sub.name}"
                        if scoped in ignore_list:
                            continue
                        if any(scoped.startswith(prefix) for prefix in SKIP_PACKAGE_PREFIXES):
                            continue
                        results[scoped] = scan_package_dir(sub)
            elif item.is_dir():
                if item.name in ignore_list:
                    continue
                results[item.name] = scan_package_dir(item)

    return results
