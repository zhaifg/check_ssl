# -*- encoding: utf-8 -*-
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from verify_domain_cert.skill import SKILL_MD, SKILL_NAME, default_skill_dir, install_skill


class InstallSkillTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_writes_valid_skill_md(self):
        skill_file = install_skill(self.tmp / SKILL_NAME)

        self.assertTrue(skill_file.is_file())
        self.assertEqual(skill_file.name, "SKILL.md")
        content = skill_file.read_text(encoding="utf-8")
        self.assertTrue(content.startswith("---\n"))
        self.assertIn(f"name: {SKILL_NAME}", content)
        self.assertIn("description: Check TLS/SSL certificates", content)
        self.assertIn("verify_domain_cert https://www.google.com", content)

    def test_creates_missing_parent_directories(self):
        target = self.tmp / "nested" / "skills" / SKILL_NAME
        skill_file = install_skill(target)

        self.assertEqual(skill_file, target / "SKILL.md")
        self.assertTrue(skill_file.is_file())

    def test_refuses_to_overwrite_without_force(self):
        target = self.tmp / SKILL_NAME
        install_skill(target)

        with self.assertRaises(FileExistsError):
            install_skill(target)

        install_skill(target, force=True)
        self.assertTrue((target / "SKILL.md").is_file())

    def test_default_dir_is_portable_agents_location(self):
        default = default_skill_dir()

        self.assertEqual(default.name, SKILL_NAME)
        self.assertEqual(default.parent, Path.home() / ".agents" / "skills")

    def test_module_entrypoint_installs_skill(self):
        target = self.tmp / SKILL_NAME
        result = subprocess.run(
            [sys.executable, "-m", "verify_domain_cert.skill", "--dir", str(target)],
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("installed agent skill", result.stdout)
        self.assertTrue((target / "SKILL.md").is_file())

    def test_skill_md_generated_content_matches_fixture(self):
        target = self.tmp / SKILL_NAME
        skill_file = install_skill(target)

        self.assertEqual(skill_file.read_text(encoding="utf-8"), SKILL_MD)
