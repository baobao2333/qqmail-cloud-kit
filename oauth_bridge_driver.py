#!/usr/bin/env python3
"""Optional POSIX bridge to the official CLI's hidden callback stdin.

The bridge keeps callback data in memory/private FIFOs and discards raw CLI logs.
The official client separately persists OAuth credentials according to config.toml.
The current authorization URL is displayed only for the user's current login.
"""
import argparse
import json
import os
from pathlib import Path
import re
import select
import shlex
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlencode, urlsplit
from oauth_bridge_common import (
    validate_authorization_url, validate_callback, verify_private_fifo,
    verify_private_directory, require_posix, requested_scopes,
)

PROOF_STATE = 'SYNTHETIC_PROOF_STATE_0123456789'
PROOF_CHALLENGE = 'A' * 43
PROOF_CODE = 'SYNTHETIC_PROOF_CODE'


def cli_command(proof, enable_send=False):
    scopes = ' '.join(sorted(requested_scopes(enable_send)))
    if proof:
        url = 'https://wx.mail.qq.com/oauth/authorize?' + urlencode({
            'response_type': 'code', 'client_id': 'synthetic-proof-client',
            'redirect_uri': 'http://127.0.0.1:14556/callback', 'scope': scopes,
            'state': PROOF_STATE, 'code_challenge': PROOF_CHALLENGE,
            'code_challenge_method': 'S256',
        })
        program = ('import sys; from urllib.parse import urlsplit,parse_qs; '
                   'print(' + repr(url) + ',flush=True); '
                   'q=parse_qs(urlsplit(sys.stdin.readline().strip()).query); '
                   'sys.exit(0 if q.get("code")==[' + repr(PROOF_CODE) + '] and '
                   'q.get("state")==[' + repr(PROOF_STATE) + '] else 2)')
        return [sys.executable, '-u', '-c', program]
    return [os.environ.get('CODEX_BIN', 'codex'), 'mcp', 'login', 'qqmail',
            '--scopes', scopes.replace(' ', ','), '--oauth-client-registration', 'dcr', '--no-browser']


def run_bridge(proof, home, run_directory=None, timeout=600, enable_send=False, command=None):
    require_posix()
    verify_private_directory(home)
    previous_umask = os.umask(0o077)
    run = None
    process = None
    read_fd = None
    pipes = []
    try:
        if run_directory:
            run = Path(run_directory).absolute()
            if run.parent != home or not run.name.startswith('oauth-'):
                raise ValueError('Unexpected private run directory')
            verify_private_directory(run)
        else:
            run = Path(tempfile.mkdtemp(prefix='oauth-', dir=home))
        control, callback = run / 'control.fifo', run / 'callback.fifo'
        for path in (control, callback):
            if not run_directory:
                os.mkfifo(path, 0o600)
                pipes.append(path)
            verify_private_fifo(path)
        read_fd = os.open(callback, os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW)
        print('PRIVATE_RUN_DIRECTORY', run, flush=True)
        receiver = Path(__file__).resolve().parent / 'oauth_bridge_receiver.py'
        print('RECEIVER_COMMAND ' + shlex.join([sys.executable, str(receiver), str(run)]), flush=True)
        process = subprocess.Popen(
            command or cli_command(proof, enable_send), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=home,
            env={**os.environ, 'CODEX_HOME': str(home), 'RUST_LOG': 'error', 'RUST_LOG_STYLE': 'never'}, bufsize=0,
        )
        streams = [process.stdout.fileno(), process.stderr.fileno()]
        buffers = {fd: b'' for fd in streams}
        for fd in streams:
            os.set_blocking(fd, False)
        packet = b''
        expected = None
        control_sent = False
        callback_sent = False
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if expected is not None and not control_sent:
                try:
                    out = os.open(control, os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
                except OSError:
                    pass
                else:
                    try:
                        payload = json.dumps(expected, separators=(',', ':')).encode('utf-8') + b'\n'
                        if os.write(out, payload) != len(payload):
                            raise RuntimeError('Private control delivery failed')
                    finally:
                        os.close(out)
                    control_sent = True
                    print('PRIVATE_CALLBACK_CHANNEL_READY', flush=True)
            ready, _, _ = select.select(streams + [read_fd], [], [], 0.2)
            for fd in ready:
                if fd == read_fd:
                    part = os.read(read_fd, 16384)
                    if part:
                        packet += part
                        if len(packet) > 16384 or callback_sent:
                            raise RuntimeError('Unexpected private callback packet')
                        if b'\n' in packet:
                            value = json.loads(packet.decode('utf-8'))
                            if expected is None or set(value) != {'callback_url'}:
                                raise RuntimeError('Unexpected private callback fields')
                            parsed = urlsplit(value['callback_url'])
                            target = parsed.path + ('?' + parsed.query if parsed.query else '')
                            canonical = validate_callback(target, parsed.netloc, expected)
                            if canonical != value['callback_url']:
                                raise RuntimeError('Unexpected private callback URL')
                            process.stdin.write(canonical.encode('utf-8') + b'\n')
                            process.stdin.flush()
                            process.stdin.close()
                            callback_sent = True
                            packet = b''
                            print('HARMLESS_CALLBACK_SUBMITTED' if proof else 'CALLBACK_SUBMITTED_TO_OFFICIAL_CLIENT', flush=True)
                else:
                    chunk = os.read(fd, 8192)
                    if not chunk:
                        streams.remove(fd)
                        continue
                    if expected is None:
                        buffers[fd] += chunk
                        if sum(map(len, buffers.values())) > 131072:
                            raise RuntimeError('Official output exceeded startup limit')
                        match = re.search(rb'https://wx\.mail\.qq\.com/oauth/authorize[^\s\x1b<>]+(?=[\s\x1b<>])', buffers[fd])
                        if match:
                            url = match.group().decode('ascii')
                            expected = validate_authorization_url(url, enable_send)
                            buffers.clear()
                            print('OAUTH_SCOPES_VERIFIED ' + ' '.join(sorted(requested_scopes(enable_send))), flush=True)
                            if proof:
                                print('HARMLESS_PROOF_CALLBACK_URL http://127.0.0.1:14556/callback?' + urlencode({'code': PROOF_CODE, 'state': PROOF_STATE}), flush=True)
                            else:
                                print('AUTHORIZATION_URL ' + url, flush=True)
                    # Subsequent official-client logs are discarded.
            code = process.poll()
            if code is not None and not streams:
                if code == 0 and callback_sent:
                    print('HARMLESS_BRIDGE_PROOF_VERIFIED' if proof else 'OFFICIAL_QQ_LOGIN_SUCCEEDED', flush=True)
                    return 0
                print('OFFICIAL_CLIENT_EXITED_WITHOUT_VERIFIED_LOGIN', flush=True)
                return 1
        print('LOGIN_TIMED_OUT', flush=True)
        return 1
    except Exception:
        # Exceptions may carry auth data. Never print them or their traceback.
        print('LOCAL_OAUTH_BRIDGE_STOPPED_SAFELY', flush=True)
        return 1
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
        if read_fd is not None:
            os.close(read_fd)
        for path in pipes:
            path.unlink(missing_ok=True)
        if run is not None and not run_directory:
            try:
                run.rmdir()
            except OSError:
                pass
        os.umask(previous_umask)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('proof', 'login'))
    parser.add_argument('run_directory', nargs='?')
    parser.add_argument('--enable-send', action='store_true', help='Explicitly request mail:send in addition to the read-only defaults')
    parser.add_argument('--timeout', type=int, default=600, help='One-shot timeout in seconds (1..600)')
    args = parser.parse_args(argv)
    if not 1 <= args.timeout <= 600:
        parser.error('timeout must be between 1 and 600')
    try:
        require_posix()
        home = Path(os.environ.get('QQMAIL_CODEX_HOME', str(Path.home() / '.codex-qqmail'))).expanduser().absolute()
        return run_bridge(args.mode == 'proof', home, args.run_directory, args.timeout, args.enable_send)
    except (ValueError, RuntimeError, OSError):
        print('BRIDGE_START_FAILED: requires POSIX and a private dedicated 0700 home', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
