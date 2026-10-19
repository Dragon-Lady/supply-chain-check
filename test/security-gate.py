"""Exercise scanner import isolation against candidate-controlled Python modules."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HELPER = Path(__file__).resolve().parents[1] / '.github/scripts/check-package.sh'

class ScannerIsolationTests(unittest.TestCase):
    def test_candidate_modules_never_replace_range_or_package_scanner(self):
        for shadow in ('push_guard.py', 'push_guard/__main__.py', 'sitecustomize.py'):
            for location in ('range', 'package'):
                with self.subTest(shadow=shadow, location=location), tempfile.TemporaryDirectory() as td:
                    root = Path(td)
                    def git(*args):
                        return subprocess.check_output(['git', *args], cwd=root, stderr=subprocess.DEVNULL, text=True).strip()
                    git('init', '-q')
                    git('config', 'user.name', 'Dragon Lady')
                    git('config', 'user.email', '268074749+Dragon-Lady@users.noreply.github.com')
                    (root / 'package.json').write_text('{"name":"inert-scan-fixture","version":"1.0.0","files":["src/"]}')
                    (root / 'src').mkdir()
                    (root / 'src/clean.txt').write_text('ordinary package content')
                    git('add', '.')
                    git('commit', '-qm', 'Add inert fixture')
                    base = git('rev-parse', 'HEAD')
                    attack = root / shadow
                    attack.parent.mkdir(exist_ok=True)
                    if attack.parent != root:
                        (attack.parent / '__init__.py').write_text('')
                    attack.write_text("from pathlib import Path\nPath('SHADOW_EXECUTED').touch()\nimport os\nos._exit(0)\n")
                    token = 'gh' + 'p_' + 'Ab3d' * 9
                    if location == 'range':
                        (root / 'src/canary.txt').write_text(token)
                    git('add', '.')
                    git('commit', '-qm', 'Add inert shadow fixture')
                    if location == 'package':
                        (root / 'src/canary.txt').write_text(token)
                    env = os.environ | {'PUSH_GUARD_INFER_IDENTITY': '0'}
                    env.pop('REQUIRE_PRIVATE_TERMS', None)
                    result = subprocess.run(['bash', str(HELPER), base], cwd=root, env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn('secret.github_token', result.stderr)
                    self.assertNotIn(token, result.stdout + result.stderr)
                    self.assertFalse((root / 'SHADOW_EXECUTED').exists())

if __name__ == '__main__':
    unittest.main()
