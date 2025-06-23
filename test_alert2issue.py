import unittest
from unittest.mock import patch, mock_open

from alert2issue import (
    load_repos,
    ensure_label,
    create_issue,
)


class TestScriptLogic(unittest.TestCase):

    def test_load_repos(self):
        fake_data = "# comment\nuser/repo1\nuser/repo2  # inline\n\n"
        with patch("builtins.open", mock_open(read_data=fake_data)):
            result = load_repos("fakefile.txt")
            self.assertEqual(result, ["user/repo1", "user/repo2"])

    @patch("alert2issue.subprocess.run")
    def test_ensure_label_skips_if_exists(self, mock_run):
        mock_run.return_value = unittest.mock.Mock(
            stdout="security\tcolor\tdescription", returncode=0
        )
        ensure_label("test/repo", "security", "d73a4a", "desc", dry_run=False)
        mock_run.assert_called_once()  # Only `gh label list` should be called

    @patch("alert2issue.subprocess.run")
    def test_ensure_label_creates_new(self, mock_run):
        mock_run.side_effect = [
            unittest.mock.Mock(stdout="", returncode=0),  # label list
            unittest.mock.Mock(returncode=0),  # label create
        ]
        ensure_label("test/repo", "new-label", "abc123", "desc", dry_run=False)
        self.assertEqual(mock_run.call_count, 2)
        args = mock_run.call_args_list[1][0][0]
        self.assertIn("label", args)
        self.assertIn("create", args)

    @patch("alert2issue.subprocess.run")
    def test_create_issue_dry_run(self, mock_run):
        create_issue(
            "test/repo", "Test Title", "Test Body", dry_run=True, labels=["security"]
        )
        mock_run.assert_not_called()

    @patch("alert2issue.subprocess.run")
    def test_create_issue_actual(self, mock_run):
        mock_run.return_value = unittest.mock.Mock(returncode=0)
        create_issue(
            "test/repo", "Test Title", "Test Body", dry_run=False, labels=["security"]
        )
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        self.assertIn("--repo", args)
        self.assertIn("test/repo", args)
        self.assertIn("--title", args)
        self.assertIn("Test Title", args)


if __name__ == "__main__":
    unittest.main()
