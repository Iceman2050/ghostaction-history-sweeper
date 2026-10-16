"""Tests for ghostaction-history-sweeper.

Builds a throwaway git fixture repo with planted secrets across several commits
(including one deleted later — a history-only leak) and asserts the scanner
finds every one of them.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from history_sweeper import scan_repo, dedupe, render_checklist  # noqa: E402


SECRETS = {
    "aws": ("config/deploy.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'),
    "github": (".env", "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890"),
    "gitlab": (".env", "GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxx"),
    "anthropic": ("app.py", 'client = Anthropic(api_key="sk-ant-api03-abcdefghijklmnopqrstuvwx")'),
    "xai": ("app.py", 'XAI_KEY = "xai-abcdefghijklmnopqrstuvwx"'),
    "openai": ("app.py", 'OPENAI_KEY = "sk-abcdefghijklmnopqrstuvwx123456"'),
    "generic": ("settings.py", 'db_password = "s3cur3H1ghEntr0pyP4ssw0rd"'),
}


def git(repo, *args, env=None):
    e = dict(os.environ)
    e.update({
        "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "t@t.t",
        "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "t@t.t",
    })
    if env:
        e.update(env)
    subprocess.run(["git", "-C", repo, *args], check=True,
                   capture_output=True, env=e)


def commit_file(repo, path, content, msg, date):
    full = os.path.join(repo, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "a") as fh:
        fh.write(content + "\n")
    git(repo, "add", path)
    git(repo, "commit", "-m", msg, env={
        "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date})


class SweeperTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = tempfile.mkdtemp(prefix="sweeper-fixture-")
        git(cls.repo, "init", "-q")
        # Commit 1: AWS key in a file
        commit_file(cls.repo, *SECRETS["aws"], "add deploy config", "2024-01-02T10:00:00")
        # Commit 2: GitHub + GitLab tokens
        commit_file(cls.repo, *SECRETS["github"], "add env", "2024-02-02T10:00:00")
        commit_file(cls.repo, *SECRETS["gitlab"], "add gitlab token", "2024-03-02T10:00:00")
        # Commit 3: AI keys + generic password
        commit_file(cls.repo, *SECRETS["anthropic"], "wire anthropic", "2024-04-02T10:00:00")
        commit_file(cls.repo, *SECRETS["xai"], "wire xai", "2024-05-02T10:00:00")
        commit_file(cls.repo, *SECRETS["openai"], "wire openai", "2024-06-02T10:00:00")
        commit_file(cls.repo, *SECRETS["generic"], "settings", "2024-07-02T10:00:00")
        # Commit 4: "remove" the secrets file — history-only leak from here on
        os.remove(os.path.join(cls.repo, ".env"))
        git(cls.repo, "rm", "-q", ".env")
        git(cls.repo, "commit", "-qm", "remove env",
            env={"GIT_AUTHOR_DATE": "2024-08-02T10:00:00",
                 "GIT_COMMITTER_DATE": "2024-08-02T10:00:00"})

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.repo, ignore_errors=True)

    def _types(self):
        return {f.secret_type for f in dedupe(scan_repo(self.repo))}

    def test_finds_aws_key(self):
        self.assertIn("AWS Access Key ID", self._types())

    def test_finds_github_token_deleted_later(self):
        # .env was deleted in the last commit — must still be found in history
        hits = [f for f in dedupe(scan_repo(self.repo))
                if f.secret_type == "GitHub token"]
        self.assertTrue(any(".env" in f.file for f in hits),
                        "history-only GitHub token leak was missed")

    def test_finds_gitlab_token(self):
        self.assertIn("GitLab token", self._types())

    def test_finds_anthropic_key(self):
        self.assertIn("Anthropic API key", self._types())

    def test_finds_xai_key(self):
        self.assertIn("xAI API key", self._types())

    def test_finds_openai_key(self):
        self.assertIn("OpenAI-style API key", self._types())

    def test_finds_generic_password(self):
        self.assertIn("Generic high-entropy secret", self._types())

    def test_all_seven_types_found(self):
        self.assertEqual(len(self._types()), 7)

    def test_context_pairing_lines_present(self):
        for f in dedupe(scan_repo(self.repo)):
            self.assertGreaterEqual(len(f.context), 1,
                                    f"no context captured for {f.secret_type}")

    def test_since_filter_excludes_old_commits(self):
        new_only = dedupe(scan_repo(self.repo, since="2024-06-15"))
        types = {f.secret_type for f in new_only}
        self.assertNotIn("AWS Access Key ID", types)
        self.assertNotIn("GitHub token", types)

    def test_checklist_mentions_each_finding(self):
        findings = dedupe(scan_repo(self.repo))
        report = render_checklist(findings, self.repo, None)
        for f in findings:
            self.assertIn(f.secret_type, report)
            self.assertIn(f.commit[:12], report)
            self.assertIn(f.suggestion, report)

    def test_commit_hash_and_file_in_findings(self):
        findings = dedupe(scan_repo(self.repo))
        aws = [f for f in findings if f.secret_type == "AWS Access Key ID"]
        self.assertTrue(aws)
        self.assertEqual(len(aws[0].commit), 40)
        self.assertIn("deploy.py", aws[0].file)

    def test_not_a_git_repo_fails(self):
        with self.assertRaises(SystemExit):
            scan_repo(tempfile.gettempdir())


if __name__ == "__main__":
    unittest.main(verbosity=2)
