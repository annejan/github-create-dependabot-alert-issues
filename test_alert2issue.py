import unittest
from unittest.mock import patch, mock_open, Mock
import subprocess
import sys
import io

import alert2issue


class TestScriptLogic(unittest.TestCase):
    def test_load_repos(self):
        fake_data = "# comment\nuser/repo1\nuser/repo2  # inline\n\n"
        with patch("builtins.open", mock_open(read_data=fake_data)):
            result = alert2issue.load_repos("fakefile.txt")
            self.assertEqual(result, ["user/repo1", "user/repo2"])

    @patch("alert2issue.subprocess.run")
    def test_ensure_label_skips_if_exists(self, mock_run):
        mock_run.return_value = Mock(stdout="security\tcolor\tdescription", returncode=0)
        alert2issue.ensure_label("test/repo", "security", "d73a4a", "desc", dry_run=False)
        mock_run.assert_called_once()

    @patch("alert2issue.subprocess.run")
    def test_ensure_label_creates_new(self, mock_run):
        mock_run.side_effect = [
            Mock(stdout="", returncode=0),  # label list
            Mock(returncode=0),  # label create
        ]
        alert2issue.ensure_label("test/repo", "new-label", "abc123", "desc", dry_run=False)
        self.assertEqual(mock_run.call_count, 2)
        args = mock_run.call_args_list[1][0][0]
        self.assertIn("label", args)
        self.assertIn("create", args)

    @patch("alert2issue.subprocess.run")
    def test_create_issue_dry_run(self, mock_run):
        alert2issue.create_issue("test/repo", "Test Title", "Test Body", dry_run=True, labels=["security"])
        mock_run.assert_not_called()

    @patch("alert2issue.subprocess.run")
    def test_create_issue_actual(self, mock_run):
        mock_run.return_value = Mock(returncode=0)
        alert2issue.create_issue("test/repo", "Test Title", "Test Body", dry_run=False, labels=["security"])
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        self.assertIn("--repo", args)
        self.assertIn("test/repo", args)
        self.assertIn("--title", args)
        self.assertIn("Test Title", args)

    @patch("alert2issue.subprocess.run")
    def test_run_gh_command_success(self, mock_run):
        mock_run.return_value = Mock(stdout='{"key": "value"}', returncode=0)
        result = alert2issue.run_gh_command("gh test")
        self.assertEqual(result, {"key": "value"})

    @patch("alert2issue.subprocess.run", side_effect=subprocess.CalledProcessError(1, "gh test", stderr="error"))
    def test_run_gh_command_failure(self, mock_run):
        result = alert2issue.run_gh_command("gh test")
        self.assertIsNone(result)

    @patch("alert2issue.run_gh_command")
    def test_process_repo_no_alerts(self, mock_run):
        mock_run.side_effect = [[], None]  # Empty alert list
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            alert2issue.process_repo("user/repo")
            self.assertIn("No open dependabot alerts", mock_stdout.getvalue())

    @patch("alert2issue.run_gh_command")
    @patch("alert2issue.ensure_label")
    @patch("alert2issue.create_issue")
    def test_process_repo_with_alert(self, mock_create, mock_label, mock_run):
        mock_run.side_effect = [
            [  # Alerts
                {
                    "state": "open",
                    "created_at": "2024-01-01T00:00:00Z",
                    "html_url": "https://github.com/example/alert",
                    "security_vulnerability": {
                        "package": {"name": "package1", "ecosystem": "npm"},
                        "vulnerable_version_range": "<1.0.0",
                        "first_patched_version": {"identifier": "1.0.0"},
                    },
                    "security_advisory": {
                        "severity": "HIGH",
                        "identifiers": [{"type": "CVE", "value": "CVE-2024-0001"}],
                    },
                }
            ],
            None,  # No existing issue
        ]
        alert2issue.process_repo("user/repo", dry_run=True)
        mock_create.assert_called_once()
        mock_label.assert_any_call("user/repo", "security", "d73a4a", "Security-related issues", True)

    @patch("alert2issue.run_gh_command")
    @patch("alert2issue.ensure_label")
    @patch("alert2issue.create_issue")
    def test_process_repo_no_patch(self, mock_create, mock_label, mock_run):
        mock_run.side_effect = [
            [  # Alerts with no patch
                {
                    "state": "open",
                    "created_at": "2024-01-01T00:00:00Z",
                    "html_url": "https://github.com/example/alert",
                    "security_vulnerability": {
                        "package": {"name": "package1", "ecosystem": "npm"},
                        "vulnerable_version_range": "<1.0.0",
                        "first_patched_version": None,
                    },
                    "security_advisory": {
                        "severity": "LOW",
                        "identifiers": [],
                    },
                }
            ],
            None,  # No existing issue
        ]
        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            alert2issue.process_repo("user/repo", dry_run=True)
            self.assertIn("no patched version", mock_out.getvalue().lower())

    @patch("alert2issue.process_repo")
    def test_main_missing_file(self, mock_process):
        with patch("sys.argv", ["script", "missing.txt"]), patch("pathlib.Path.exists", return_value=False), patch("sys.stdout", new_callable=io.StringIO) as out:
            alert2issue.main()
            self.assertIn("File not found", out.getvalue())
            mock_process.assert_not_called()

    @patch("alert2issue.process_repo")
    def test_main_with_file(self, mock_process):
        with patch("sys.argv", ["script", "repos.txt"]), patch("pathlib.Path.exists", return_value=True), patch("alert2issue.load_repos", return_value=["user/repo"]):
            alert2issue.main()
            mock_process.assert_called_once_with("user/repo", dry_run=False)


if __name__ == "__main__":
    unittest.main()
