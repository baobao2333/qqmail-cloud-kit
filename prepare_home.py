#!/usr/bin/env python3
"""Create a NEW isolated POSIX Codex home without changing existing connections."""
import argparse
import os
from pathlib import Path
import sys
from oauth_bridge_common import requested_scopes, require_posix


def create_home(destination, enable_send=False):
    require_posix()
    destination = Path(destination).expanduser().absolute()
    # Refuse even an empty existing path: never overwrite an existing Codex home.
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    previous_umask = os.umask(0o077)
    try:
        source = Path(__file__).resolve().parent / 'config.example.toml'
        config = source.read_text(encoding='utf-8')
        if enable_send:
            config = config.replace('scopes = ["alias:read", "mail:read"]', 'scopes = ["alias:read", "mail:read", "mail:send"]')
        (destination / 'config.toml').write_text(config, encoding='utf-8')
        (destination / 'config.toml').chmod(0o600)
        (destination / 'requests').mkdir(mode=0o700)
        (destination / 'mail-runtime').mkdir(mode=0o700)
    finally:
        os.umask(previous_umask)
    return destination


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', required=True, help='New private directory; parent must already exist')
    parser.add_argument('--enable-send', action='store_true')
    args = parser.parse_args(argv)
    try:
        create_home(args.home, args.enable_send)
    except (OSError, RuntimeError):
        print('PREPARE_HOME_FAILED: requires POSIX, an existing parent and a new directory', file=sys.stderr)
        return 2
    print('NEW_PRIVATE_HOME_READY scopes=' + ','.join(sorted(requested_scopes(args.enable_send))))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
