#!/usr/bin/env python3
"""Build a deterministic, explicit-whitelist source ZIP and SHA256 file."""
import argparse
import hashlib
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parents[1]
RELEASE_FILES = (
    '.gitattributes', '.gitignore', '.github/workflows/offline-tests.yml',
    'VERSION', 'README.md', 'SECURITY.md', 'CHANGES.md',
    'config.example.toml', 'oauth_bridge_common.py', 'oauth_bridge_driver.py',
    'oauth_bridge_receiver.py', 'check_qqmail.py', 'redaction.py', 'prepare_home.py',
    'docs/QUICKSTART.md', 'docs/HEADLESS.md', 'docs/LIMITATIONS.md',
    'scripts/build_release.py',
    'tests/test_oauth_validation.py', 'tests/test_redaction.py',
    'tests/test_readonly.py', 'tests/test_bridge_exit.py', 'tests/test_release.py',
)
TOKEN_PATTERN = re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{24,})\b')
PRIVATE_KEY_PATTERN = re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')
EMAIL_PATTERN = re.compile(r'[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})')


def source_bytes(root, relative):
    path = root / relative
    if path.is_symlink() or not path.is_file() or root not in path.resolve().parents:
        raise ValueError('Missing or unsafe release file: ' + relative)
    content = path.read_bytes()
    text = content.decode('utf-8')
    if '\r' in text:
        raise ValueError('Release source must use LF newlines: ' + relative)
    if TOKEN_PATTERN.search(text) or PRIVATE_KEY_PATTERN.search(text):
        raise ValueError('Possible credential material in release file: ' + relative)
    for match in EMAIL_PATTERN.finditer(text):
        if match.group(1).lower() not in {'example.com', 'example.net', 'example.org', 'invalid', 'users.noreply.github.com'}:
            raise ValueError('Possible personal email in release file: ' + relative)
    if re.search(r'(?i)[a-z]:[\\/]+Users[\\/]+[^\\/\s]+', text):
        raise ValueError('Personal machine path in release file: ' + relative)
    return content


def build(root=ROOT, output=None):
    root = Path(root).resolve()
    version = (root / 'VERSION').read_text(encoding='utf-8').strip()
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('VERSION must be a numeric semantic version')
    content = [(relative, source_bytes(root, relative)) for relative in sorted(RELEASE_FILES)]
    output = Path(output or root / 'dist').resolve()
    output.mkdir(parents=True, exist_ok=True)
    basename = 'qqmail-cloud-kit-' + version
    archive = output / (basename + '.zip')
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_STORED) as package:
        for relative, data in content:
            info = zipfile.ZipInfo(basename + '/' + relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_STORED
            package.writestr(info, data)
    with zipfile.ZipFile(archive) as package:
        if package.testzip() is not None or len(package.namelist()) != len(RELEASE_FILES):
            raise ValueError('Release ZIP validation failed')
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum = output / (basename + '.sha256')
    checksum.write_text(digest + '  ' + archive.name + '\n', encoding='ascii')
    return archive, checksum, digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='Output directory; default: dist')
    args = parser.parse_args()
    archive, checksum, digest = build(output=args.output)
    print(archive)
    print(checksum)
    print('SHA256 ' + digest)


if __name__ == '__main__':
    main()
