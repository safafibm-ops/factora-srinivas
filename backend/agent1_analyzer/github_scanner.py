"""
Factora Agent 1: GitHub Repository & Dependency Supply-Chain Malware Scanner
Protects students and developers from fraudulent job/assessment repositories:
1. GitHub REST API metadata & anomaly inspection (repo age, stars, suspicious fork).
2. VS Code workspace traps (.vscode/tasks.json configured with 'runOn: folderOpen').
3. Package lifecycle hook backdoors in package.json (preinstall, postinstall, prepare).
4. Python setup.py code execution hooks and typosquatted dependencies.
"""

import os
import re
import json
import base64
import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any, Tuple
from urllib.parse import urlparse

import requests


# Known malicious or typosquatted npm/pip package patterns frequently used in recruitment scams
SUSPICIOUS_PACKAGE_PATTERNS = [
    r"cross-env-stealer", r"node-fetch-override", r"discord-selfbot",
    r"colors-v2", r"event-stream-patch", r"request-lite", r"ua-parser-stealer",
    r"chalk-legacy", r"axois", r"lodsh", r"expres", r"requsts", r"beautifullsoup",
    r"fask", r"py-cord-token"
]

MALICIOUS_EXEC_PATTERNS = [
    r"curl\s+.*\|\s*(?:ba)?sh",
    r"wget\s+.*\|\s*(?:ba)?sh",
    r"powershell(?:\.exe)?\s+.*-(?:enc|encodedcommand|w\s+hidden)",
    r"certutil(?:\.exe)?\s+-urlcache",
    r"eval\s*\(\s*(?:atob|buffer\.from)",
    r"process\.env\.(?:npm_config_|discord_|telegram_|aws_|github_)",
    r"webhook\.discord\.com/api/webhooks",
    r"socket\.connect\s*\(",
    r"os\.system\s*\(\s*['\"]curl",
    r"subprocess\.(?:popen|run|call)\s*\(.*powershell"
]


class GitHubAssessmentScanner:
    """Audits GitHub repositories submitted to students for job coding assessments."""

    def __init__(self, github_token: Optional[str] = None):
        self.token = github_token or os.getenv("GITHUB_TOKEN")
        self.headers = {"User-Agent": "Factora-SupplyChain-Auditor/1.0"}
        if self.token:
            self.headers["Authorization"] = f"Bearer {self.token}"

    @staticmethod
    def parse_github_url(repo_url: str) -> Optional[Tuple[str, str]]:
        """Extracts (owner, repo) from GitHub URL."""
        clean = repo_url.strip().rstrip("/")
        match = re.search(r"github\.com[/:]([\w\.\-]+)/([\w\.\-]+?)(?:\.git)?$", clean, re.IGNORECASE)
        if match:
            return match.group(1), match.group(2)
        return None

    def fetch_repo_metadata(self, owner: str, repo: str) -> Dict[str, Any]:
        """Fetches repository metadata from the GitHub API."""
        api_url = f"https://api.github.com/repos/{owner}/{repo}"
        try:
            resp = requests.get(api_url, headers=self.headers, timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                created_at = data.get("created_at")
                pushed_at = data.get("pushed_at")
                age_days = None
                if created_at:
                    dt = datetime.datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ")
                    age_days = (datetime.datetime.utcnow() - dt).days

                return {
                    "full_name": data.get("full_name"),
                    "owner": owner,
                    "repo": repo,
                    "created_at": created_at,
                    "pushed_at": pushed_at,
                    "age_days": age_days,
                    "is_fresh_repo": (age_days is not None and age_days < 30),
                    "stars": data.get("stargazers_count", 0),
                    "forks": data.get("forks_count", 0),
                    "is_fork": data.get("fork", False),
                    "default_branch": data.get("default_branch", "main"),
                    "description": data.get("description", ""),
                    "archived": data.get("archived", False)
                }
            elif resp.status_code == 404:
                return {"error": "Repository not found or is private."}
            else:
                return {"error": f"GitHub API status {resp.status_code}: {resp.text[:100]}"}
        except Exception as e:
            return {"error": str(e)}

    def fetch_raw_file(self, owner: str, repo: str, branch: str, file_path: str) -> Optional[str]:
        """
        Fetches raw content of a file directly from raw.githubusercontent.com
        (Bypasses REST API rate limits).
        """
        raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}"
        try:
            resp = requests.get(raw_url, headers={"User-Agent": "Factora-Auditor/1.0"}, timeout=6)
            if resp.status_code == 200:
                return resp.text
        except Exception:
            pass

        # Fallback to GitHub Contents API
        api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}?ref={branch}"
        try:
            resp = requests.get(api_url, headers=self.headers, timeout=6)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("encoding") == "base64" and data.get("content"):
                    return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        except Exception:
            pass

        return None

    def scan_vscode_tasks(self, owner: str, repo: str, branch: str) -> Dict[str, Any]:
        """
        Scans .vscode/tasks.json for 'runOn: folderOpen' traps.
        If a user opens the cloned workspace in VS Code with trust enabled,
        tasks marked with 'folderOpen' execute shell commands instantly without prompting.
        """
        content = self.fetch_raw_file(owner, repo, branch, ".vscode/tasks.json")
        if not content:
            return {"found": False, "is_malicious": False, "note": ".vscode/tasks.json not found"}

        has_folder_open = bool(re.search(r"['\"]runOn['\"]\s*:\s*['\"]folderOpen['\"]", content, re.IGNORECASE))
        has_exec_hook = any(re.search(p, content, re.IGNORECASE) for p in MALICIOUS_EXEC_PATTERNS)

        # Parse tasks to extract exact offending commands
        suspicious_commands = []
        try:
            parsed = json.loads(content)
            tasks = parsed.get("tasks", [])
            for t in tasks:
                cmd = str(t.get("command", ""))
                args = " ".join(str(a) for a in t.get("args", []))
                full_cmd = f"{cmd} {args}".strip()
                run_opts = t.get("runOptions", {})
                runs_on_open = run_opts.get("runOn") == "folderOpen"

                if runs_on_open or any(re.search(p, full_cmd, re.IGNORECASE) for p in MALICIOUS_EXEC_PATTERNS):
                    suspicious_commands.append({
                        "label": t.get("label", "unnamed"),
                        "command": full_cmd,
                        "runs_on_folder_open": runs_on_open
                    })
        except Exception:
            if has_folder_open or has_exec_hook:
                suspicious_commands.append({"raw_snippet": content[:300]})

        is_critical = has_folder_open or bool(suspicious_commands)

        return {
            "found": True,
            "is_malicious": is_critical,
            "has_folder_open_autoexec": has_folder_open,
            "suspicious_commands": suspicious_commands,
            "severity": "CRITICAL / REMOTE CODE EXECUTION" if is_critical else "INFORMATIONAL",
            "warning": (
                "CRITICAL WARNING: This repository contains .vscode/tasks.json configured to execute code "
                "automatically upon opening the folder! Do NOT open this repository in VS Code."
                if is_critical else None
            )
        }

    def scan_package_json(self, owner: str, repo: str, branch: str) -> Dict[str, Any]:
        """
        Scans package.json for dangerous npm lifecycle hooks (preinstall, postinstall, prepare)
        and suspicious typosquatted package dependencies.
        """
        content = self.fetch_raw_file(owner, repo, branch, "package.json")
        if not content:
            return {"found": False, "is_malicious": False, "note": "package.json not found"}

        findings = []
        suspicious_packages = []
        dangerous_hooks = []

        try:
            pkg = json.loads(content)
            scripts = pkg.get("scripts", {})
            lifecycle_hooks = ["preinstall", "install", "postinstall", "prepare", "prepack"]

            for hook in lifecycle_hooks:
                if hook in scripts:
                    hook_cmd = str(scripts[hook])
                    has_suspicious_payload = any(re.search(p, hook_cmd, re.IGNORECASE) for p in MALICIOUS_EXEC_PATTERNS)
                    dangerous_hooks.append({
                        "hook": hook,
                        "command": hook_cmd,
                        "is_dangerous": has_suspicious_payload or any(w in hook_cmd.lower() for w in ["curl", "powershell", "wget", "eval", "sh", "node -e"])
                    })

            # Check dependencies & devDependencies
            all_deps = {}
            all_deps.update(pkg.get("dependencies", {}))
            all_deps.update(pkg.get("devDependencies", {}))

            for dep_name, version in all_deps.items():
                for pat in SUSPICIOUS_PACKAGE_PATTERNS:
                    if re.search(pat, dep_name, re.IGNORECASE):
                        suspicious_packages.append(dep_name)
                # Check for direct external URL or git tarball dependencies
                if isinstance(version, str) and any(version.startswith(p) for p in ["git+", "http://", "https://"]):
                    findings.append(f"External non-npm dependency link: '{dep_name}': '{version}'")

        except Exception as e:
            findings.append(f"Error parsing package.json: {e}")

        is_malicious = any(h["is_dangerous"] for h in dangerous_hooks) or bool(suspicious_packages)

        return {
            "found": True,
            "is_malicious": is_malicious,
            "dangerous_hooks": dangerous_hooks,
            "suspicious_packages": suspicious_packages,
            "findings": findings,
            "warning": (
                "MALICIOUS NPM HOOKS IDENTIFIED: Running 'npm install' on this repository will execute "
                "hidden commands designed to harvest browser cookies or install remote backdoors."
                if is_malicious else None
            )
        }

    def scan_python_manifests(self, owner: str, repo: str, branch: str) -> Dict[str, Any]:
        """Scans requirements.txt and setup.py for code-execution traps."""
        setup_content = self.fetch_raw_file(owner, repo, branch, "setup.py")
        reqs_content = self.fetch_raw_file(owner, repo, branch, "requirements.txt")

        findings = []
        is_malicious = False

        if setup_content:
            for pat in MALICIOUS_EXEC_PATTERNS:
                if re.search(pat, setup_content, re.IGNORECASE):
                    is_malicious = True
                    findings.append(f"setup.py executes untrusted shell payload matching: {pat}")

        if reqs_content:
            for line in reqs_content.splitlines():
                line = line.strip()
                if line.startswith(("-e", "http://", "https://", "git+")):
                    findings.append(f"Direct remote pip requirement: {line}")
                for pat in SUSPICIOUS_PACKAGE_PATTERNS:
                    if re.search(pat, line, re.IGNORECASE):
                        is_malicious = True
                        findings.append(f"Typosquatted or malicious pip package: {line}")

        return {
            "has_setup_py": setup_content is not None,
            "has_requirements_txt": reqs_content is not None,
            "is_malicious": is_malicious,
            "findings": findings
        }

    def audit_repository(self, repo_url: str) -> Dict[str, Any]:
        """
        Runs comprehensive full-spectrum supply chain analysis on a target GitHub repository URL.
        Returns unified threat verdict, metadata risks, VS Code traps, and package hooks.
        """
        parsed = self.parse_github_url(repo_url)
        if not parsed:
            return {
                "repo_url": repo_url,
                "is_valid_github_url": False,
                "error": "Not a valid GitHub repository URL."
            }

        owner, repo = parsed
        meta = self.fetch_repo_metadata(owner, repo)
        branch = meta.get("default_branch", "main") if "error" not in meta else "main"

        vscode_scan = self.scan_vscode_tasks(owner, repo, branch)
        npm_scan = self.scan_package_json(owner, repo, branch)
        python_scan = self.scan_python_manifests(owner, repo, branch)

        is_critical = (
            vscode_scan.get("is_malicious", False) or
            npm_scan.get("is_malicious", False) or
            python_scan.get("is_malicious", False)
        )

        red_flags = []
        if meta.get("is_fresh_repo"):
            red_flags.append(f"Repository created only {meta.get('age_days')} days ago (disposable recruitment assessment lure).")
        if meta.get("stars", 0) == 0:
            red_flags.append("Repository has 0 stars and no organic community history.")
        if vscode_scan.get("has_folder_open_autoexec"):
            red_flags.append("CRITICAL: .vscode/tasks.json triggers silent auto-execution upon opening workspace in VS Code.")
        if npm_scan.get("dangerous_hooks"):
            red_flags.append("CRITICAL: package.json lifecycle hooks execute commands during 'npm install'.")
        if npm_scan.get("suspicious_packages"):
            red_flags.append(f"Malicious packages detected: {', '.join(npm_scan.get('suspicious_packages', []))}")

        return {
            "repo_url": repo_url,
            "owner": owner,
            "repo": repo,
            "is_valid_github_url": True,
            "metadata": meta,
            "vscode_tasks_scan": vscode_scan,
            "npm_manifest_scan": npm_scan,
            "python_manifest_scan": python_scan,
            "is_compromised_repo": is_critical,
            "severity": "CRITICAL RISK" if is_critical else ("CAUTION" if red_flags else "SAFE"),
            "red_flags": red_flags,
            "safe_to_clone": not is_critical
        }

