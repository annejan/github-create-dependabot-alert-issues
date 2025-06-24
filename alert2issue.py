#!/usr/bin/env python3

import argparse
import json
import shlex
import subprocess
from pathlib import Path


def run_gh_command(cmd: str, capture_json: bool = True) -> str | dict | None:
    """Run a GitHub CLI command and return the output as JSON or plain text."""
    try:
        result = subprocess.run(shlex.split(cmd), capture_output=True, check=True, text=True)
        return json.loads(result.stdout) if capture_json else result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"❌ Command failed: {cmd}")
        if e.stderr:
            print(e.stderr)
        return None


def run_gh_command_json(cmd: str) -> list[dict] | None:
    """Run a GitHub CLI command and return the output as JSON."""
    output = run_gh_command(cmd, capture_json=True)
    if output is None:
        return None

    return output if isinstance(output, list) else json.loads(output)


def run_gh_command_text(cmd: str) -> str | None:
    """Run a GitHub CLI command and return the output as plain text."""
    output = run_gh_command(cmd, capture_json=False)
    if output is None:
        return None

    return output if isinstance(output, str) else json.dumps(output, indent=2)


def check_rate_limit(min_remaining: int = 100) -> bool:
    """Check GitHub API rate limit and return True if sufficient calls remaining."""
    print("⏳ Checking GitHub API rate limit...")
    remaining = run_gh_command_text('gh api rate_limit --jq ".rate.remaining"')
    if remaining is None:
        print("⚠️ Could not determine API rate limit. Proceeding with caution.")
        return True

    try:
        remaining_int = int(remaining)
        print(f"🔢 API calls remaining: {remaining_int}")
        if remaining_int < min_remaining:
            print(f"❌ API rate limit too low (<{min_remaining}). Aborting.")
            return False
        return True
    except ValueError:
        print(f"⚠️ Unexpected rate limit value: {remaining}. Proceeding.")
        return True


def ensure_label(
    repo: str, label: str, color: str, description: str, dry_run: bool = False
) -> None:
    """Ensure a label exists in the specified repository."""
    existing = run_gh_command_text(f"gh label list --repo {repo} --limit 100")
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


def create_issue(
    repo: str, title: str, body: str, dry_run: bool = False, labels: list[str] | None = None
) -> None:
    """Create a new issue in the specified repository."""
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


def get_open_issue_titles(repo: str) -> set[str]:
    """Get titles of all open issues in the specified repository."""
    # Get all open issue titles for repo in one go (up to 100)
    output = run_gh_command_json(f"gh issue list --repo {repo} --state open --json title")
    if output is None:
        return set()

    return set(issue["title"] for issue in output)


def process_repo(repo: str, dry_run: bool = False) -> None:
    """Process a single repository to check for Dependabot alerts and create issues."""
    print(f"🔍 Checking alerts for: {repo}")

    alerts = run_gh_command_json(
        f'gh api -X GET "/repos/{repo}/dependabot/alerts?per_page=100" --paginate',
    )
    if not alerts:
        print(f"✅ No open dependabot alerts found for {repo}.")
        return

    open_issues = get_open_issue_titles(repo)

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

        if title in open_issues:
            print(f"⚠️  Issue already exists in {repo}: '{title}'. Skipping...")
            continue

        labels = [
            {
                "name": "security",
                "color": "d73a4a",
                "description": "Security-related issues",
            },
            {
                "name": "dependabot",
                "color": "0366d6",
                "description": "Dependabot alerts",
            },
        ]

        if fpv is None:
            labels.append(
                {
                    "name": "no-patch",
                    "color": "ededed",
                    "description": "No patched version available",
                }
            )

        for label in labels:
            ensure_label(repo, label["name"], label["color"], label["description"], dry_run)

        create_issue(repo, title, body, dry_run=dry_run, labels=[label["name"] for label in labels])


def load_repos(path: Path) -> list[str]:
    """Load repository names from a file, ignoring comments and empty lines."""
    with open(path, "r", encoding="utf-8") as f:
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
        "-d",
        action="store_true",
        help="Print actions but don't make any changes",
    )
    parser.add_argument(
        "--min-rate-limit",
        "-m",
        type=int,
        default=100,
        help="Minimum remaining GitHub API calls required to proceed (default: 100)",
    )
    args = parser.parse_args()

    path = Path(args.repo_file)
    if not path.exists():
        print(f"❌ File not found: {args.repo_file}")
        return

    if not check_rate_limit(min_remaining=args.min_rate_limit):
        print("❌ Exiting due to low GitHub API rate limit. Please try again later.")
        return

    for repo in load_repos(path):
        process_repo(repo, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
