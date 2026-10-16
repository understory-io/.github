import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml


class SecretScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workflow = Path(__file__).resolve().parents[1] / ".github/workflows/secret-scan.yml"
        cls.command = yaml.safe_load(workflow.read_text())["jobs"]["secret-scan"]["steps"][1]["run"]
        cls.scratch = Path(os.environ["SCAN_TEST_ROOT"]).resolve()
        cls.scratch.mkdir(parents=True, exist_ok=True)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=self.scratch)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.runtime = self.root / "runtime"
        self.runtime.mkdir()
        self.git("init", "-q")
        self.git("config", "user.email", "scanner-test@example.invalid")
        self.git("config", "user.name", "Scanner regression")
        (self.repo / "README.md").write_text("Isolated scanner fixture.\n")
        self.commit()

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True, text=True)

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")

    def scan(self, cwd=None):
        return subprocess.run(
            ["bash", "-c", self.command], cwd=cwd or self.repo,
            env={**os.environ, "RUNNER_TEMP": str(self.runtime)},
            capture_output=True, text=True, timeout=120,
        )

    def test_clean_history_passes(self):
        result = self.scan()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Secret scan passed", result.stdout)
        self.assertEqual(list(self.runtime.iterdir()), [])

    def test_deleted_secret_and_repository_ignores_cannot_pass(self):
        synthetic = "ghp_" + "Ab3dE5gH7jK9mN2pQ4sT6vW8xY1zC0fR5uL7"
        (self.repo / "credential.txt").write_text(synthetic + " # gitleaks:allow\n")
        (self.repo / ".gitleaks.toml").write_text('[allowlist]\npaths = [".*"]\n')
        self.commit()
        revision = self.git("rev-parse", "HEAD").stdout.strip()
        fingerprint = f"{revision}:credential.txt:github-pat:1"
        (self.repo / ".gitleaksignore").write_text(fingerprint + "\n")
        (self.repo / "credential.txt").unlink()
        self.commit()
        result = self.scan()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn(synthetic, result.stdout + result.stderr)
        findings = json.JSONDecoder().raw_decode(result.stdout)[0]
        self.assertIn(
            {"path": "credential.txt", "type": "github-pat", "fingerprint": fingerprint},
            findings,
        )
        self.assertTrue(all(set(item) == {"path", "type", "fingerprint"} for item in findings))
        self.assertEqual(list(self.runtime.iterdir()), [])

    def test_scanner_error_is_not_a_clean_scan(self):
        not_a_repository = self.root / "not-a-repository"
        not_a_repository.mkdir()
        result = self.scan(cwd=not_a_repository)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Secret scan passed", result.stdout)
        self.assertEqual(list(self.runtime.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
