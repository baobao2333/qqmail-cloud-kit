import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from build_release import build, RELEASE_FILES, ROOT, source_bytes


class ReleaseTests(unittest.TestCase):
    def test_reproducible_zip_and_exact_whitelist(self):
        with tempfile.TemporaryDirectory() as temporary:
            first, checksum, digest = build(output=Path(temporary) / 'one')
            second, _, second_digest = build(output=Path(temporary) / 'two')
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(digest, second_digest)
            self.assertEqual(hashlib.sha256(first.read_bytes()).hexdigest(), digest)
            self.assertEqual(checksum.read_text().strip(), digest + '  ' + first.name)
            with zipfile.ZipFile(first) as package:
                members = [name.split('/', 1)[1] for name in package.namelist()]
                self.assertEqual(set(members), set(RELEASE_FILES))
                self.assertNotIn('config.toml', members)
                self.assertNotIn('.credentials.json', members)

    def test_personal_email_and_credential_shapes_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            file = root / 'synthetic.txt'
            for text in ('synthetic_person' + '@' + 'synthetic-test-domain.test', 'ghp_' + 'A' * 30):
                file.write_text(text, encoding='utf-8')
                with self.assertRaises(ValueError):
                    source_bytes(root, 'synthetic.txt')

    def test_no_undeclared_project_files(self):
        actual = {str(path.relative_to(ROOT)).replace('\\', '/') for path in ROOT.rglob('*') if path.is_file() and not any(part in {'.git', '__pycache__', 'dist'} for part in path.relative_to(ROOT).parts)}
        self.assertEqual(actual, set(RELEASE_FILES))


if __name__ == '__main__':
    unittest.main()
