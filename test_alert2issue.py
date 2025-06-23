import subprocess
import unittest
from unittest.mock import Mock, mock_open, patch

import alert2issue


@patch("builtins.print")
class TestScriptLogic(unittest.TestCase):
    def test_load_repos(self, mock_print):
        fake_data = "# comment\nuser/repo1\nuser/repo2  # inline\n\n"
        with patch("builtins.open", mock_open(read_data=fake_data)):
            result = alert2issue.load_repos("fakefile.txt")
            self.assertEqual(result, ["user/repo1", "user/repo2"])

    @patch("alert2issue.subprocess.run")
    def test_ensure_label_skips_if_exists(self, mock_run, mock_print):
        mock_run.return_value = Mock(stdout="security\tcolor\tdescription", returncode=0)
        alert2issue.ensure_label("test/repo", "security", "d73a4a", "desc", dry_run=False)
        mock_run.assert_called_once()

    @patch("alert2issue.subprocess.run")
    def test_ensure_label_creates_new(self, mock_run, mock_print):
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
    def test_create_issue_dry_run(self, mock_run, mock_print):
        alert2issue.create_issue(
            "test/repo", "Test Title", "Test Body", dry_run=True, labels=["security"]
        )
        mock_run.assert_not_called()

    @patch("alert2issue.subprocess.run")
    def test_create_issue_actual(self, mock_run, mock_print):
        mock_run.return_value = Mock(returncode=0)
        alert2issue.create_issue(
            "test/repo", "Test Title", "Test Body", dry_run=False, labels=["security"]
        )
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        self.assertIn("--repo", args)
        self.assertIn("test/repo", args)
        self.assertIn("--title", args)
        self.assertIn("Test Title", args)

    @patch("alert2issue.subprocess.run")
    def test_run_gh_command_success(self, mock_run, mock_print):
        mock_run.return_value = Mock(stdout='{"key": "value"}', returncode=0)
        result = alert2issue.run_gh_command("gh test")
        self.assertEqual(result, {"key": "value"})

    @patch(
        "alert2issue.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "gh test", stderr="error"),
    )
    def test_run_gh_command_failure(self, mock_run, mock_print):
        result = alert2issue.run_gh_command("gh test")
        self.assertIsNone(result)

    @patch("alert2issue.run_gh_command")
    def test_process_repo_no_alerts(self, mock_run, mock_print):
        mock_run.side_effect = [[], None]  # Empty alert list
        alert2issue.process_repo("user/repo")
        print_calls = [call.args[0] for call in mock_print.call_args_list]
        self.assertTrue(
            any("No open dependabot alerts" in msg for msg in print_calls),
            "Expected 'No open dependabot alerts' in printed output.",
        )

    @patch("alert2issue.run_gh_command")
    @patch("alert2issue.ensure_label")
    @patch("alert2issue.create_issue")
    def test_process_repo_with_alert(self, mock_create, mock_label, mock_run, mock_print):
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
        mock_label.assert_any_call(
            "user/repo", "security", "d73a4a", "Security-related issues", True
        )

    @patch("alert2issue.run_gh_command")
    @patch("alert2issue.ensure_label")
    @patch("alert2issue.create_issue")
    def test_process_repo_no_patch(self, mock_create, mock_label, mock_run, mock_print):
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
        alert2issue.process_repo("user/repo", dry_run=True)
        print_calls = [call.args[0].lower() for call in mock_print.call_args_list]
        self.assertTrue(
            any("no patched version" in msg for msg in print_calls),
            "Expected 'no patched version' in printed output.",
        )

    @patch("alert2issue.process_repo")
    def test_main_missing_file(self, mock_process, mock_print):
        with (
            patch("sys.argv", ["script", "missing.txt"]),
            patch("pathlib.Path.exists", return_value=False),
        ):
            alert2issue.main()
            mock_print.assert_any_call("❌ File not found: missing.txt")
            mock_process.assert_not_called()

    @patch("alert2issue.process_repo")
    def test_main_with_file(self, mock_process, mock_print):
        with (
            patch("sys.argv", ["script", "repos.txt"]),
            patch("pathlib.Path.exists", return_value=True),
            patch("alert2issue.load_repos", return_value=["user/repo"]),
        ):
            alert2issue.main()
            mock_process.assert_called_once_with("user/repo", dry_run=False)

    @patch("alert2issue.run_gh_command")
    def test_check_rate_limit_ok(self, mock_run, mock_print):
        mock_run.return_value = "150"
        result = alert2issue.check_rate_limit(min_remaining=100)
        self.assertTrue(result)
        mock_print.assert_any_call("⏳ Checking GitHub API rate limit...")
        mock_print.assert_any_call("🔢 API calls remaining: 150")

    @patch("alert2issue.run_gh_command")
    def test_check_rate_limit_low(self, mock_run, mock_print):
        mock_run.return_value = "50"
        result = alert2issue.check_rate_limit(min_remaining=100)
        self.assertFalse(result)
        mock_print.assert_any_call("❌ API rate limit too low (<100). Aborting.")

    @patch("alert2issue.run_gh_command")
    def test_check_rate_limit_none(self, mock_run, mock_print):
        mock_run.return_value = None
        result = alert2issue.check_rate_limit(min_remaining=100)
        self.assertTrue(result)
        mock_print.assert_any_call("⚠️ Could not determine API rate limit. Proceeding with caution.")

    @patch("alert2issue.run_gh_command")
    def test_check_rate_limit_bad_value(self, mock_run, mock_print):
        mock_run.return_value = "not-an-int"
        result = alert2issue.check_rate_limit(min_remaining=100)
        self.assertTrue(result)
        mock_print.assert_any_call("⚠️ Unexpected rate limit value: not-an-int. Proceeding.")

    @patch("alert2issue.check_rate_limit")
    def test_main_exits_on_low_rate_limit(self, mock_check_rate_limit, mock_print):
        mock_check_rate_limit.return_value = False
        with (
            patch("sys.argv", ["script", "repos.txt"]),
            patch("pathlib.Path.exists", return_value=True),
        ):
            alert2issue.main()
        mock_print.assert_any_call(
            "❌ Exiting due to low GitHub API rate limit. Please try again later."
        )

    @patch("alert2issue.check_rate_limit")
    @patch("alert2issue.load_repos", return_value=["user/repo"])
    @patch("alert2issue.process_repo")
    def test_main_runs_when_rate_limit_ok(
        self, mock_process_repo, mock_load_repos, mock_check_rate_limit, mock_print
    ):
        mock_check_rate_limit.return_value = True
        with (
            patch("sys.argv", ["script", "repos.txt"]),
            patch("pathlib.Path.exists", return_value=True),
        ):
            alert2issue.main()
        mock_process_repo.assert_called_once_with("user/repo", dry_run=False)

    @patch("alert2issue.check_rate_limit")
    @patch("pathlib.Path.exists", return_value=True)
    @patch("alert2issue.load_repos", return_value=["user/repo"])
    @patch("alert2issue.process_repo")
    def test_main_min_rate_limit_arg(
        self, mock_process, mock_load, mock_exists, mock_check_rate_limit, mock_print
    ):
        mock_check_rate_limit.return_value = True
        with patch("sys.argv", ["script", "repos.txt", "--min-rate-limit", "50"]):
            alert2issue.main()
        mock_check_rate_limit.assert_called_once_with(min_remaining=50)
        mock_process.assert_called_once_with("user/repo", dry_run=False)


if __name__ == "__main__":
    unittest.main()
