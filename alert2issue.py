#!/usr/bin/env python3

import argparse
import json
import shlex
import subprocess
from pathlib import Path


def run_gh_command(cmd, capture_json=True):
    try:
        result = subprocess.run(shlex.split(cmd), capture_output=True, check=True, text=True)
        return json.loads(result.stdout) if capture_json else result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"❌ Command failed: {cmd}")
        print(e.stderr)
        return None


def ensure_label(repo, label, color, description, dry_run=False):
    existing = run_gh_command(f"gh label list --repo {repo} --limit 100", capture_json=False)
    if not existing or not any(line.startswith(label) for line in existing.splitlines()):
        action = "Would create" if dry_run else "Creating"
        print(f"🛠️ {action} label: {label} in {repo}")
        if dry_run:
            return
        try:
            subprocess.run(
                [
                    "gh",
                    "label",
                    "create",
                    label,
                    "--repo",
                    repo,
                    "--color",
                    color,
                    "--description",
                    description,
                ],
                check=True,
            )
        except subprocess.CalledProcessError:
            print(f"⚠️  Failed to create label: {label} in {repo}")


def create_issue(repo, title, body, dry_run=False, labels=None):
    labels = labels or ["security", "dependabot"]

    if dry_run:
        print(
            f"📝 Would create issue in {repo}:\n  Title: {title}\n  Labels: {labels}\n  Body (truncated): {body[:100]}..."
        )
        return

    args = ["gh", "issue", "create", "--repo", repo, "--title", title, "--body", body]
    for label in labels:
        args.extend(["--label", label])

    try:
        subprocess.run(args, check=True)
        print(f"📝 Created issue in {repo}: {title}")
    except subprocess.CalledProcessError:
        print(f"❌ Failed to create issue in {repo}: {title}")


def process_repo(repo, dry_run=False):
    print(f"🔍 Checking alerts for: {repo}")
    alerts = run_gh_command(
        f'gh api -X GET "/repos/{repo}/dependabot/alerts?per_page=100" --paginate',
        capture_json=True,
    )
    if not alerts:
        print(f"✅ No open dependabot alerts found for {repo}.")
        return

    for alert in alerts:
        if alert.get("state") != "open":
            continue

        pkg = alert["security_vulnerability"]["package"]["name"]
        eco = alert["security_vulnerability"]["package"]["ecosystem"]
        sev = alert["security_advisory"]["severity"]
        range_ = alert["security_vulnerability"]["vulnerable_version_range"]
        created = alert["created_at"]
        url = alert["html_url"]

        fpv = alert["security_vulnerability"].get("first_patched_version")
        if fpv is None:
            print(f"⚠️  No patched version listed for {pkg} in {repo} (vulnerable range: {range_})")
        patched = fpv.get("identifier", "Not specified") if fpv else "Not specified"

        cves = (
            ", ".join(
                i["value"] for i in alert["security_advisory"]["identifiers"] if i["type"] == "CVE"
            )
            or "None"
        )

        title = f"[Dependabot] Security Alert for: {pkg} ({eco})"
        body = f"""**Package:** {pkg} ({eco})

**Severity:** {sev}
**Created At:** {created}
**CVE(s):** {cves}
**Affected Versions:** {range_}
**First Patched Version:** {patched}

[View Alert]({url})
"""

        existing = run_gh_command(
            f'gh issue list --repo {repo} --search "{title} in:title" --state open --json title --jq ".[0].title"',
            capture_json=False,
        )
        if existing == title:
            print(f"⚠️  Issue already exists in {repo}: '{title}'. Skipping...")
            continue

        ensure_label(repo, "security", "d73a4a", "Security-related issues", dry_run)
        ensure_label(repo, "dependabot", "0366d6", "Dependabot alerts", dry_run)

        labels = ["security", "dependabot"]
        if fpv is None:
            ensure_label(repo, "no-patch", "ededed", "No patched version available", dry_run)
            labels.append("no-patch")

        create_issue(repo, title, body, dry_run=dry_run, labels=labels)


def load_repos(path):
    with open(path) as f:
        return [
            line.split("#")[0].strip()
            for line in f
            if line.strip() and not line.strip().startswith("#")
        ]


def main():
    parser = argparse.ArgumentParser(
        description="Check GitHub repos for Dependabot alerts and file issues."
    )
    parser.add_argument("repo_file", help="File containing list of GitHub repositories")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print actions but don't make any changes",
    )
    args = parser.parse_args()

    path = Path(args.repo_file)
    if not path.exists():
        print(f"❌ File not found: {args.repo_file}")
        return

    for repo in load_repos(path):
        process_repo(repo, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
