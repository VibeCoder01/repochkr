"""
Manifest detection and dependency extraction helpers.

Each handler returns a list of normalized dependency records:
{
    "ecosystem": "npm" | "pypi" | "maven" | "go" | "cargo" | ...,
    "name": "package-name",
    "version": "x.y.z",
    "scope": "runtime" | "dev" | "test",
    "manifest_path": "path/to/manifest"
}
"""

from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional


Dependency = Dict[str, str]
Handler = Callable[[str, str], List[Dependency]]


def _clean_version(version: str) -> str:
    if not isinstance(version, str):
        return str(version)
    v = version.strip()
    # Strip common semver operators for lookups/display.
    v = re.sub(r"^[~^><=\\s]+", "", v)
    return v or version


def _normalize_dep(ecosystem: str, name: str, version: str, scope: str, manifest_path: str) -> Dependency:
    return {
        "ecosystem": ecosystem,
        "name": name.strip(),
        "version": _clean_version(version),
        "scope": scope,
        "manifest_path": manifest_path,
    }


def parse_package_json(content: str, path: str) -> List[Dependency]:
    data = json.loads(content)
    deps = []
    for section, scope in (("dependencies", "runtime"), ("devDependencies", "dev")):
        for name, version in data.get(section, {}).items():
            deps.append(_normalize_dep("npm", name, version, scope, path))
    return deps


def parse_requirements_txt(content: str, path: str) -> List[Dependency]:
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.split(r"(==|>=|<=|~=|!=)", line, maxsplit=1)
        if len(match) >= 3:
            name, version = match[0], match[2]
        else:
            name, version = line, "*"
        deps.append(_normalize_dep("pypi", name, version, "runtime", path))
    return deps


def parse_pyproject_toml(content: str, path: str) -> List[Dependency]:
    data = tomllib.loads(content)
    deps = []
    project = data.get("project", {})
    for entry in project.get("dependencies", []):
        if isinstance(entry, str):
            parts = re.split(r"(==|>=|<=|~=|!=)", entry, maxsplit=1)
            if len(parts) >= 3:
                name, version = parts[0], parts[2]
            else:
                name, version = entry, "*"
            deps.append(_normalize_dep("pypi", name, version, "runtime", path))
    opt = project.get("optional-dependencies", {})
    for _, items in opt.items():
        for entry in items:
            name = entry.split(" ")[0]
            deps.append(_normalize_dep("pypi", name, entry, "dev", path))
    poetry = data.get("tool", {}).get("poetry", {})
    for section, scope in (("dependencies", "runtime"), ("dev-dependencies", "dev")):
        for name, version in poetry.get(section, {}).items():
            if name == "python":
                continue
            deps.append(_normalize_dep("pypi", name, str(version), scope, path))
    return deps


def parse_pipfile(content: str, path: str) -> List[Dependency]:
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError:
        # Pipfile.lock is JSON; fall back to json loader
        data = json.loads(content)
    deps = []
    for section, scope in (("packages", "runtime"), ("dev-packages", "dev")):
        section_data = data.get(section, {}) or data.get("default", {}) if section == "packages" else data.get("develop", {})
        for name, version in section_data.items():
            if isinstance(version, dict):
                version_str = version.get("version", "*")
            else:
                version_str = version if isinstance(version, str) else "*"
            deps.append(_normalize_dep("pypi", name, version_str, scope, path))
    return deps


def parse_poetry_lock(content: str, path: str) -> List[Dependency]:
    """Parse poetry.lock to capture pinned versions."""
    data = tomllib.loads(content)
    deps = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version", "*")
        if not name:
            continue
        deps.append(_normalize_dep("pypi", name, version, "runtime", path))
    return deps


def parse_go_mod(content: str, path: str) -> List[Dependency]:
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("//") or line.startswith("module"):
            continue
        if line.startswith("require"):
            line = line.replace("require", "", 1).strip().strip("(").strip(")")
            continue
        parts = line.split()
        if len(parts) >= 2:
            deps.append(_normalize_dep("go", parts[0], parts[1], "runtime", path))
    return deps


def parse_cargo_toml(content: str, path: str) -> List[Dependency]:
    data = tomllib.loads(content)
    deps = []
    for section, scope in (
        ("dependencies", "runtime"),
        ("dev-dependencies", "dev"),
        ("build-dependencies", "runtime"),
    ):
        for name, version in data.get(section, {}).items():
            version_str = version if isinstance(version, str) else "*"
            deps.append(_normalize_dep("cargo", name, version_str, scope, path))
    return deps


def parse_pom_xml(content: str, path: str) -> List[Dependency]:
    deps = []
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return deps
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    for dep in root.findall(".//m:dependency", namespaces=ns):
        group = dep.findtext("m:groupId", default="", namespaces=ns)
        artifact = dep.findtext("m:artifactId", default="", namespaces=ns)
        version = dep.findtext("m:version", default="*", namespaces=ns)
        scope = dep.findtext("m:scope", default="runtime", namespaces=ns)
        name = f"{group}:{artifact}" if group else artifact
        deps.append(_normalize_dep("maven", name, version, scope, path))
    return deps


def parse_gradle(content: str, path: str) -> List[Dependency]:
    deps = []
    pattern = re.compile(r"(implementation|api|compileOnly|runtimeOnly|testImplementation)\s+['\"](.+):(.+):(.+)['\"]")
    for match in pattern.finditer(content):
        scope_map = {
            "implementation": "runtime",
            "api": "runtime",
            "compileOnly": "runtime",
            "runtimeOnly": "runtime",
            "testImplementation": "test",
        }
        scope = scope_map.get(match.group(1), "runtime")
        name = f"{match.group(2)}:{match.group(3)}"
        version = match.group(4)
        deps.append(_normalize_dep("maven", name, version, scope, path))
    return deps


HANDLERS: Dict[str, Handler] = {
    "package.json": parse_package_json,
    "requirements.txt": parse_requirements_txt,
    "pyproject.toml": parse_pyproject_toml,
    "Pipfile": parse_pipfile,
    "Pipfile.lock": parse_pipfile,
    "poetry.lock": parse_poetry_lock,
    "go.mod": parse_go_mod,
    "Cargo.toml": parse_cargo_toml,
    "pom.xml": parse_pom_xml,
    "build.gradle": parse_gradle,
    "build.gradle.kts": parse_gradle,
}


def detect_manifests(files: Iterable[Dict]) -> List[str]:
    """Return manifest paths discovered in a repo file listing."""
    manifests = []
    for f in files:
        name = f.get("name")
        if name in HANDLERS or (name and name.startswith("requirements") and name.endswith(".txt")):
            manifests.append(f["path"])
    return manifests


def parse_manifest(path: str, content: str) -> List[Dependency]:
    """Dispatch to the correct handler based on file name."""
    handler = HANDLERS.get(Path(path).name)
    if not handler:
        return []
    try:
        return handler(content, path)
    except Exception:
        # Return partial data on parser errors
        return []
