# alert2issue

🔐 Automatically create GitHub issues from open Dependabot alerts — complete with severity, CVE info, and tagging.

[![PyPI version](https://badge.fury.io/py/alert2issue.svg)](https://badge.fury.io/py/alert2issue)

---

## 🚀 What It Does

`alert2issue` scans a list of GitHub repositories for open [Dependabot alerts](https://docs.github.com/en/code-security/dependabot) and creates labeled GitHub issues summarizing the problems.

It helps teams stay on top of security alerts by converting them into visible, actionable tasks.

---

### ✨ Key Labels

When creating issues, it applies useful labels to improve visibility:

- **`security`** General security issue
- **`dependabot`** Marks it as coming from a Dependabot alert
- **`no-patch`** Special label if no fix is available for the vulnerability

This helps teams triage and prioritize issues more easily within GitHub.

---

## 📦 Features

- ✅ Lists open Dependabot alerts using the GitHub CLI
- ✅ Avoids duplicate issues
- ✅ Auto-labels issues with `security` and `dependabot`
- ✅ Marks alerts with `no-patch` as special warnings
- ✅ Supports dry-run mode for safe testing
- ✅ Tested with unit tests and >80% coverage

---

## ✅ Requirements

- Python 3.8+
- GitHub CLI (`gh`)
- GitHub token with `repo` scope if using private repositories

---

## 📦 Installation

Install via [PyPI](https://pypi.org/project/alert2issue/):

```bash
pip install alert2issue
```

Make sure you have the [GitHub CLI](https://cli.github.com/) (`gh`) installed and authenticated:

```bash
gh auth login
```

---

## ⚙️ Usage

```bash
# Quick example
echo "annejan/woo_data_playground" > repos.txt
alert2issue repos.txt
# ✅ Created issue: "[Dependabot] Security Alert for: requests (pip)"
```

Run the tool with a list of repositories (one per line):

```bash
alert2issue path/to/repo-list.txt
```

You can also pass options:

```bash
alert2issue -d -m 200 repos.txt
```

### 🛠 Options

| Short | Long                   | Description                                                             |
| ----- | ---------------------- | ----------------------------------------------------------------------- |
| `-d`  | `--dry-run`            | Run without creating issues or labels (preview only)                    |
| `-m`  | `--min-rate-limit MIN` | Minimum number of GitHub API calls required to proceed (default: `100`) |

#### 🧠 About `--min-rate-limit`

GitHub’s API has [rate limits](https://docs.github.com/en/rest/overview/resources-in-the-rest-api#rate-limiting), especially for authenticated requests.

Use `--min-rate-limit` to **avoid starting work if the remaining quota is too low**, this is useful for automation and CI environments.

If the current rate limit is below the provided minimum, the script exits early with a warning.

This ensures you have enough API calls left before processing begins so you don't break other more important automation.

---

### 📄 Example repo list file content

```text
# Only include public or authorized repos
annejan/alert2issue
badgeteam/website       # Inline comment can be used
IJHack/QtPass
```

---

## 📈 CI

This project includes GitHub Actions workflows that runs tests and linting.

---

## 🛠 Development

To contribute or run from source:

```bash
git clone https://github.com/annejan/alert2issue.git
cd alert2issue
pip install -e .[dev]
```

### 🔍 Linting & Formatting

This project uses [ruff](https://docs.astral.sh/ruff/) and [black](https://black.readthedocs.io/) for code style enforcement:

```bash
# Run ruff linter
ruff check .

# Auto-fix style issues
ruff check . --fix

# Format with black
black .

# Type check
mypy *.py
```

### ✅ Testing

Run unit tests with:

```bash
python -m unittest
```

With coverage:

```bash
coverage run -m unittest
coverage report
```

---

## 🙋 Contributing

Pull requests welcome! Open an issue first if you'd like to suggest a major change.

---

## 📄 License

MIT License — see [LICENSE](./LICENSE) file.

© 2025 Anne Jan Brouwer

Parts of this project were written with the assistance of [ChatGPT](https://openai.com/chatgpt), [Claude](https://www.anthropic.com/claude) and [VLAM.ai](https://vlam.ai/).
