# alert2issue

🔐 Automatically create GitHub issues from open Dependabot alerts — complete with severity, CVE info, and tagging.

---

## 🚀 What It Does

`alert2issue` scans a list of GitHub repositories for open [Dependabot alerts](https://docs.github.com/en/code-security/dependabot) and creates labeled GitHub issues summarizing the problems.

It helps teams stay on top of security alerts by converting them into visible, actionable tasks.

---

## 📦 Features

- ✅ Lists open Dependabot alerts using the GitHub CLI
- ✅ Avoids duplicate issues
- ✅ Auto-labels issues with `security` and `dependabot`
- ✅ Marks alerts with no patch as special warnings
- ✅ Supports dry-run mode for safe testing
- ✅ Tested with unit tests and coverage

---

## 📦 Installation

Install via [PyPI](https://pypi.org/project/alert2issue/):

```bash
pip install alert2issue
````

Make sure you have the [GitHub CLI](https://cli.github.com/) (`gh`) installed and authenticated:

```bash
gh auth login
```

---

## ⚙️ Usage

Run the tool with a list of repositories (one per line):

```bash
alert2issue path/to/repo-list.txt
```

### Options

```text
--dry-run     Run without creating issues or labels (preview only)
--verbose     Print extra info
```

### Example repo list

```text
# Only include public or authorized repos
openai/gym
pallets/flask  # Inline comment OK
```

---

## ✅ Requirements

- Python 3.8+
- GitHub CLI (`gh`)
- GitHub token with `repo` scope if using private repositories

---

## 🧪 Testing

To run tests:

```bash
python -m unittest test_alert2issue.py
```

With code coverage:

```bash
coverage run -m unittest
coverage report
```

---

## 📈 CI

This project includes a GitHub Actions workflow that runs tests and linting.

---

## 🛠 Development Install (optional)

If you want to run it from source:

```bash
git clone https://github.com/annejan/alert2issue.git
cd alert2issue
pip install -e .
```

---

## 🙋 Contributing

Pull requests welcome! Open an issue first if you'd like to suggest a major change.

---

## 📄 License

MIT License — see [LICENSE](./LICENSE) file.

© 2025 Anne Jan Brouwer

Parts of this project were written with the assistance of [ChatGPT](https://openai.com/chatgpt), [Claude](https://www.anthropic.com/claude) and [VLAM.ai](https://vlam.ai/).
