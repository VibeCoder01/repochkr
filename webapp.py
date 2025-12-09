"""
FastHTML entry point for the GitHub dependency auditor.

Routes:
- GET / : entry form
- POST /scan : perform scan and render dashboard + summaries
- GET /export/json : export the most recent results as JSON
- GET /export/md : export a Markdown summary

The app is synchronous for simplicity; the scanning pipeline is modular so it can
be moved to background jobs or queues later.
"""

from __future__ import annotations

import datetime as dt
import os
import requests
import re
from typing import Dict, List

from fasthtml.common import (
    A,
    Body,
    Button,
    Div,
    Form,
    H1,
    H2,
    H3,
    Head,
    Html,
    Input,
    JSONResponse,
    Li,
    Label,
    Link,
    Main,
    Option,
    P,
    Script,
    Select,
    Span,
    Style,
    Table,
    Tbody,
    Td,
    Th,
    Thead,
    Title,
    Tr,
    Ul,
    fast_app,
)

from dependency_parsers import detect_manifests, parse_manifest
from github_client import GitHubClient
from risk_model import repo_risk, severity_rank
from vuln_lookup import VulnerabilityLookup

app, rt = fast_app()

tailwind = Script(src="https://cdn.tailwindcss.com")

DIRECTORIES_TO_SCAN = ["", "src", "app", "backend", "frontend", "server", "client"]
_LATEST_RESULTS: Dict = {}
_PROGRESS: Dict = {"state": "idle", "message": "", "current_repo": "", "processed": 0, "total": 0}


def _layout(*body):
    return Html(
        Head(
            Title("GitHub Dependency Auditor"),
            tailwind,
            Style(
                """
                body { background: #0b1021; color: #e8ecf3; }
                .card { background: #11182c; border: 1px solid #1f2a44; }
                .pill { border-radius: 9999px; padding: 2px 10px; }
                """
            ),
        ),
        Body(
            Div(
                Div(
                    H1("GitHub Dependency Auditor", cls="text-3xl font-bold mb-2"),
                    P("Audit public repos for vulnerable dependencies with OSV data.", cls="text-slate-300"),
                    cls="mb-6",
                ),
                *body,
                cls="max-w-7xl mx-auto py-10 px-6",
            ),
            Script(
                """
                document.addEventListener("DOMContentLoaded", () => {
                    const form = document.querySelector("form[action='/scan']");
                    const statusBox = document.getElementById("status-box");
                    const statusText = document.getElementById("status-text");
                    const progressBar = document.getElementById("progress-bar");
                    const progressDetail = document.getElementById("progress-detail");
                    const submitBtn = document.getElementById("scan-submit");
                    const tokenHelpBtn = document.getElementById("token-help-toggle");
                    const tokenHelpBox = document.getElementById("token-help-box");
                    const osvHelpBtn = document.getElementById("osv-help-toggle");
                    const osvHelpBox = document.getElementById("osv-help-box");
                    const messages = [
                        "Sending request to GitHub...",
                        "Querying OSV for vulnerabilities...",
                        "Scoring repositories..."
                    ];
                    if (!form || !statusBox || !statusText) return;
                    let pollId = null;
                    form.addEventListener("submit", () => {
                        statusBox.classList.remove("hidden");
                        submitBtn?.setAttribute("disabled", "true");
                        submitBtn?.classList.add("opacity-60", "cursor-not-allowed");
                        let idx = 0;
                        statusText.textContent = messages[idx];
                        const id = setInterval(() => {
                            idx = (idx + 1) % messages.length;
                            statusText.textContent = messages[idx];
                        }, 2000);
                        // Stop cycling after a minute to avoid runaway loops on nav errors
                        setTimeout(() => clearInterval(id), 60000);
                        const poll = async () => {
                            try {
                                const resp = await fetch("/progress");
                                if (!resp.ok) return;
                                const data = await resp.json();
                                const {processed=0, total=0, current_repo="", state=""} = data;
                                const pct = total > 0 ? Math.min(100, Math.round((processed / total) * 100)) : 5;
                                if (progressBar) progressBar.style.width = `${pct}%`;
                                if (progressDetail) progressDetail.textContent = total ? `Processing ${current_repo || '...'} (${processed}/${total})` : (state || 'working...');
                            } catch (err) {
                                // swallow errors
                            }
                        };
                        poll();
                        pollId = setInterval(poll, 1200);
                        setTimeout(() => clearInterval(pollId), 120000);
                    });
                    window.addEventListener("pageshow", () => {
                        if (pollId) clearInterval(pollId);
                        if (progressBar) progressBar.style.width = "0%";
                        if (progressDetail) progressDetail.textContent = "Status: idle";
                        statusText.textContent = "Preparing scan...";
                        submitBtn?.removeAttribute("disabled");
                        submitBtn?.classList.remove("opacity-60", "cursor-not-allowed");
                    });
                    tokenHelpBtn?.addEventListener("click", () => {
                        if (!tokenHelpBox) return;
                        tokenHelpBox.classList.toggle("hidden");
                    });
                    osvHelpBtn?.addEventListener("click", () => {
                        if (!osvHelpBox) return;
                        osvHelpBox.classList.toggle("hidden");
                    });
                });
                """
            ),
        ),
    )


def severity_badge(sev: str):
    colors = {
        "CRITICAL": "bg-red-700",
        "HIGH": "bg-red-500",
        "MEDIUM": "bg-yellow-500 text-black",
        "LOW": "bg-green-600",
        "UNKNOWN": "bg-slate-500",
    }
    return Span(sev.title(), cls=f"pill text-xs font-semibold {colors.get(sev.upper(), 'bg-slate-500')}")


def render_form():
    return Div(
        Form(
            Div(
                Label("GitHub user/org", _for="owner", cls="block text-sm font-semibold text-slate-200"),
                Input(name="owner", id="owner", placeholder="octocat", required=True, cls="w-full mt-1 p-2 rounded bg-slate-900 border border-slate-700"),
                cls="w-full",
            ),
            Div(
                Label("Include forks", _for="forks", cls="block text-sm font-semibold text-slate-200"),
                Select(
                    Option("yes", value="yes"),
                    Option("no", value="no"),
                    name="forks",
                    id="forks",
                    cls="w-full mt-1 p-2 rounded bg-slate-900 border border-slate-700",
                ),
                cls="w-full md:w-1/3",
            ),
            Div(
                Label("Minimum last updated date", _for="min_updated", cls="block text-sm font-semibold text-slate-200"),
                Input(name="min_updated", id="min_updated", type="date", cls="w-full mt-1 p-2 rounded bg-slate-900 border border-slate-700"),
                cls="w-full md:w-1/3",
            ),
            Div(
                Div(
                    Label("GitHub token (fine-grained, optional)", _for="token", cls="block text-sm font-semibold text-slate-200"),
                    Button("?", type="button", id="token-help-toggle", cls="ml-2 text-xs px-2 py-1 rounded border border-slate-600 text-slate-200 hover:bg-slate-800"),
                    cls="flex items-center"
                ),
                Input(name="token", id="token", type="password", placeholder="ghp_xxx", cls="w-full mt-1 p-2 rounded bg-slate-900 border border-slate-700"),
                Div(
                    P("Used only for this scan to raise rate limits; never stored.", cls="text-slate-400 text-xs"),
                    Div(
                        H3("How to create a fine-grained token", cls="text-sm font-semibold text-slate-200 mb-1"),
                        P("1) GitHub Settings → Developer settings → Fine-grained tokens → Generate new token.", cls="text-xs text-slate-300"),
                        P("2) Name it, set expiration (short), and select the owner/org.", cls="text-xs text-slate-300"),
                        P("3) Permissions: Repository contents read-only is enough; leave others off.", cls="text-xs text-slate-300"),
                        P("4) Copy the token (starts with ghp_) and paste here for this scan.", cls="text-xs text-slate-300"),
                        cls="space-y-1 mt-2 hidden",
                        id="token-help-box",
                    ),
                cls="w-full space-y-1"),
            ),
            Button("Scan", type="submit", id="scan-submit", cls="bg-indigo-500 hover:bg-indigo-600 text-white px-4 py-2 rounded font-semibold"),
            method="post",
            action="/scan",
            cls="card p-4 grid grid-cols-1 md:grid-cols-3 gap-4",
        ),
        Div(
            Div(
                Div(cls="h-4 w-4 border-2 border-indigo-400 border-t-transparent rounded-full animate-spin"),
                Span("Preparing scan...", id="status-text", cls="text-sm text-slate-200"),
                cls="flex items-center gap-3"
            ),
            Div(
                Div(id="progress-bar", cls="h-2 bg-indigo-500 rounded-full transition-all duration-300 ease-linear", style="width: 0%"),
                cls="w-full bg-slate-800 rounded-full h-2 mt-3"
            ),
            Div(
                Span("Status: idle", id="progress-detail", cls="text-xs text-slate-400"),
                cls="mt-2"
            ),
            cls="card p-3 mt-3 hidden",
            id="status-box",
        ),
        Div(
            Div(
                Span("Data sources", cls="text-sm font-semibold text-slate-200"),
                Button("?", type="button", id="osv-help-toggle", cls="ml-2 text-xs px-2 py-1 rounded border border-slate-600 text-slate-200 hover:bg-slate-800"),
                cls="flex items-center"
            ),
            Div(
                P("Vulnerability data is fetched from OSV (api.osv.dev), which aggregates advisories from multiple ecosystems:", cls="text-xs text-slate-300"),
                Ul(
                    Li("npm: npm advisories and community contributions", cls="text-xs text-slate-300"),
                    Li("PyPI: Python Packaging Advisory Database", cls="text-xs text-slate-300"),
                    Li("Go: Go vulnerability database", cls="text-xs text-slate-300"),
                    Li("Rust: RustSec advisories", cls="text-xs text-slate-300"),
                    Li("Maven: OSV-imported JVM advisories", cls="text-xs text-slate-300"),
                    cls="list-disc list-inside space-y-1"
                ),
                P("Lookups are read-only and cached in memory per scan.", cls="text-xs text-slate-300 mt-1"),
                cls="space-y-1 mt-2 hidden",
                id="osv-help-box",
            ),
            cls="card p-3 mt-4 space-y-1"
        ),
    )


def render_error(message: str):
    return Div(
        H3("Scan failed", cls="text-lg font-semibold text-red-200"),
        P(message, cls="text-red-200"),
        P("Check your network connectivity and GitHub/OSV API access, then retry.", cls="text-slate-300 text-sm"),
        cls="card p-4 border border-red-700 bg-red-950/50"
    )


def _format_reset(ts: str) -> str:
    try:
        ts_int = int(ts)
        return dt.datetime.fromtimestamp(ts_int).isoformat()
    except Exception:
        return ts


def _version_parts(ver: str):
    base = ver.split("-", 1)[0]
    parts = []
    for chunk in base.split("."):
        m = re.match(r"([0-9]+)", chunk)
        if not m:
            return None
        parts.append(int(m.group(1)))
    return tuple(parts) if parts else None


def _is_newer_version(current: str, candidate: str) -> bool:
    cur_parts = _version_parts(current)
    cand_parts = _version_parts(candidate)
    if not cur_parts or not cand_parts:
        return True  # if we can't compare, keep the candidate
    # Pad shorter tuple with zeros for comparison
    max_len = max(len(cur_parts), len(cand_parts))
    cur = cur_parts + (0,) * (max_len - len(cur_parts))
    cand = cand_parts + (0,) * (max_len - len(cand_parts))
    return cand > cur


def render_repo_table(results: List[Dict]):
    rows = []
    for repo in results:
        rows.append(
            Tr(
                Td(A(repo["name"], href=repo["html_url"], cls="text-indigo-300 underline"), cls="whitespace-nowrap"),
                Td(repo["vulnerable_dependencies"], cls="whitespace-nowrap"),
                Td(severity_badge(repo["highest_severity"]), cls="whitespace-nowrap"),
                Td(repo["risk_score"], cls="whitespace-nowrap"),
                Td(repo["pushed_at"], cls="whitespace-nowrap"),
                cls="border-b border-slate-800",
            )
        )
    return Div(
        H2("Repositories", cls="text-xl font-semibold mb-3"),
        Table(
            Thead(
                Tr(
                    Th("Repository", cls="text-left p-2 whitespace-nowrap"),
                    Th("Vulnerable deps", cls="text-left p-2 whitespace-nowrap"),
                    Th("Highest severity", cls="text-left p-2 whitespace-nowrap"),
                    Th("Risk score", cls="text-left p-2 whitespace-nowrap"),
                    Th("Last updated", cls="text-left p-2 whitespace-nowrap"),
                )
            ),
            Tbody(*rows),
            cls="w-full text-sm",
        ),
        cls="card p-4 overflow-x-auto"
    )


def render_owner_summary(owner: str, results: List[Dict]):
    total_repos = len(results)
    vulnerable_repos = len([r for r in results if r["vulnerable_dependencies"] > 0])
    top_repos = sorted(results, key=lambda r: r["risk_score"], reverse=True)[:5]
    items = [
        Div(
            H3(r["name"], cls="font-semibold"),
            P(f"Risk {r['risk_score']} | Highest {r['highest_severity']} | Vuln deps {r['vulnerable_dependencies']}", cls="text-slate-300 text-sm"),
            cls="border-b border-slate-800 py-2",
        )
        for r in top_repos
    ]
    return Div(
        H2(f"Owner summary: {owner}", cls="text-xl font-semibold mb-2"),
        Div(
            Div(f"Total repos scanned: {total_repos}", cls="text-slate-200"),
            Div(f"Repos with vulns: {vulnerable_repos}", cls="text-slate-200"),
            Div("Priority list:", cls="text-slate-200"),
            *items,
            cls="space-y-2",
        ),
        cls="card p-4"
    )


def render_dependency_details(repo: Dict):
    rows = []
    for item in repo["dependencies"]:
        dep = item["dependency"]
        vulns = item["vulnerabilities"]
        fixes = []
        for v in vulns:
            fixes.extend(v.get("fixed_versions", []))
        # Deduplicate and show the first two recommended versions, if present
        unique_fixes = []
        seen = set()
        for fv in fixes:
            if not fv or fv in seen:
                continue
            if not _is_newer_version(dep.get("version", ""), fv):
                continue
            if len(unique_fixes) >= 2:
                continue
            seen.add(fv)
            unique_fixes.append(fv)
        recommended = ", ".join(unique_fixes[:2]) or "n/a"
        rows.append(
            Tr(
                Td(dep["name"]),
                Td(dep["version"]),
                Td(dep["ecosystem"]),
                Td(len(vulns)),
                Td(recommended),
                Td(
                    Div(
                        *[
                            Div(
                                Span(v["id"], cls="font-semibold"),
                                severity_badge(v.get("severity", "LOW")),
                                P(v["summary"], cls="text-slate-300 text-sm"),
                                Span(f"Affected: {v.get('affected_range', '')}", cls="text-xs text-slate-400"),
                                A("Advisory", href=v.get("reference_url") or "#", cls="text-indigo-300 text-xs underline"),
                                cls="space-y-1"
                            )
                            for v in vulns
                        ],
                        cls="space-y-2"
                    )
                ),
                cls="align-top border-b border-slate-800"
            )
        )
    return Div(
        H3("Dependency details", cls="text-lg font-semibold mb-3"),
        Table(
            Thead(
                Tr(
                    Th("Dependency", cls="text-left p-2 whitespace-nowrap"),
                    Th("Version", cls="text-left p-2 whitespace-nowrap"),
                    Th("Ecosystem", cls="text-left p-2 whitespace-nowrap"),
                    Th("Vuln count", cls="text-left p-2 whitespace-nowrap"),
                    Th("Recommended version", cls="text-left p-2 whitespace-nowrap"),
                    Th("Vulnerabilities", cls="text-left p-2 whitespace-nowrap"),
                )
            ),
            Tbody(*rows),
            cls="w-full text-sm"
        ),
        cls="card p-4 overflow-x-auto"
    )


def render_repo_detail(repo: Dict):
    meta = repo["meta"]
    return Div(
        H2(f"{meta.get('full_name')}", cls="text-xl font-semibold mb-3"),
        Div(
            P(meta.get("description") or "No description", cls="text-slate-300"),
            Div(
                Span(f"Language: {meta.get('language')}", cls="pill bg-slate-700 mr-2"),
                Span(f"Stars: {meta.get('stargazers_count')}", cls="pill bg-slate-700 mr-2"),
                Span(f"Last updated: {meta.get('pushed_at')}", cls="pill bg-slate-700"),
                cls="flex flex-wrap gap-2 mt-2"
            ),
            cls="mb-4"
        ),
        Div(
            Span(f"Vulnerable dependencies: {repo['vulnerable_dependencies']}", cls="pill bg-red-700"),
            Span(f"Highest severity: {repo['highest_severity']}", cls="pill bg-slate-700"),
            Span(f"Risk score: {repo['risk_score']}", cls="pill bg-indigo-700"),
            cls="flex gap-2 mb-4"
        ),
        render_dependency_details(repo),
        cls="card p-4 overflow-x-auto"
    )


def scan_owner(owner: str, include_forks: bool, min_updated: str, token: str = ""):
    min_dt = dt.datetime.fromisoformat(min_updated) if min_updated else None
    gh = GitHubClient(token=token or None)
    vulns = VulnerabilityLookup()
    repos = gh.fetch_repos(owner, include_forks=include_forks, min_updated=min_dt)
    _PROGRESS.update({"state": "scanning", "message": "Scanning repositories", "processed": 0, "total": len(repos)})
    results = []
    for repo in repos:
        _PROGRESS.update({"current_repo": repo.get("name", ""), "processed": len(results)})
        files = gh.list_repository_files(owner, repo["name"], DIRECTORIES_TO_SCAN)
        manifests = detect_manifests(files)
        dependencies = []
        for manifest in manifests:
            content = gh.fetch_file_text(owner, repo["name"], manifest)
            if not content:
                continue
            deps = parse_manifest(manifest, content)
            for dep in deps:
                vulns_for_dep = vulns.lookup(dep["ecosystem"], dep["name"], dep["version"])
                dependencies.append({"dependency": dep, "vulnerabilities": vulns_for_dep})
        scores = repo_risk(dependencies)
        results.append(
            {
                "name": repo["name"],
                "html_url": repo["html_url"],
                "pushed_at": repo["pushed_at"],
                "meta": repo,
                "dependencies": dependencies,
                **scores,
            }
        )
        _PROGRESS.update({"processed": len(results)})
    _PROGRESS.update({"state": "done", "message": "Complete", "current_repo": "", "processed": len(results)})
    return results


@rt("/")
def index():
    return _layout(
        render_form(),
        Div(
            P("Submit a scan to see dashboard, summaries, and export options.", cls="text-slate-300 mt-4"),
            cls="card p-4"
        ),
    )


@rt("/scan", methods=["POST"])
def scan(owner: str, forks: str = "yes", min_updated: str = "", token: str = ""):
    include_forks = forks != "no"
    _PROGRESS.update({"state": "starting", "message": "Starting scan", "current_repo": "", "processed": 0, "total": 0})
    try:
        results = scan_owner(owner, include_forks, min_updated, token=token)
    except RuntimeError as exc:
        msg = str(exc)
        if "rate limit" in msg.lower():
            reset_hint = msg.rsplit(" ", 1)[-1].strip(".")
            friendly = _format_reset(reset_hint) if reset_hint else "later"
            error_text = f"GitHub rate limit reached. Retry after {friendly} or provide a GITHUB_TOKEN."
        else:
            error_text = f"Unexpected error: {msg}"
        _LATEST_RESULTS.clear()
        return _layout(
            render_form(),
            render_error(error_text),
        )
    except requests.exceptions.RequestException as exc:
        _LATEST_RESULTS.clear()
        return _layout(
            render_form(),
            render_error(f"Could not reach required APIs: {exc}"),
        )
    except Exception as exc:  # noqa: BLE001
        _LATEST_RESULTS.clear()
        return _layout(
            render_form(),
            render_error(f"Unexpected error: {exc}"),
        )
    else:
        global _LATEST_RESULTS
        _LATEST_RESULTS = {"owner": owner, "results": results}
        return _layout(
            render_form(),
            Div(
                Div(
                    A("Export JSON", href="/export/json", cls="text-indigo-300 underline mr-4"),
                    A("Export Markdown", href="/export/md", cls="text-indigo-300 underline"),
                    cls="flex justify-end mb-2"
                ),
                render_owner_summary(owner, results),
                render_repo_table(results),
                *[render_repo_detail(r) for r in results],
                cls="space-y-4"
            ),
        )


@rt("/export/json")
def export_json():
    return JSONResponse(_LATEST_RESULTS or {})


@rt("/export/md")
def export_md():
    if not _LATEST_RESULTS:
        return "No results available."
    owner = _LATEST_RESULTS.get("owner")
    lines = [f"# Security report for {owner}", ""]
    for repo in _LATEST_RESULTS["results"]:
        lines.append(f"## {repo['name']} (risk {repo['risk_score']}, highest {repo['highest_severity']})")
        for item in repo["dependencies"]:
            dep = item["dependency"]
            vulns = item["vulnerabilities"]
            if not vulns:
                continue
            lines.append(f"- {dep['name']} {dep['version']} ({dep['ecosystem']}): {len(vulns)} issues")
            for v in vulns:
                fix = ", ".join(v.get("fixed_versions", [])[:1]) or "n/a"
                lines.append(f"  - {v['id']}: {v['summary']} (fix: {fix})")
        lines.append("")
    return "\n".join(lines)


@rt("/progress")
def progress():
    return JSONResponse(_PROGRESS)


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=port)
