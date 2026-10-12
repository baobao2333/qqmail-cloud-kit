"""POSIX-only subprocess proof: synthetic callbacks, no official client/network."""
import contextlib
import io
import json
import os
from pathlib import Path
import select
import sys
import tempfile
import threading
import time
import unittest
from urllib.parse import urlencode
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from oauth_bridge_driver import run_bridge, PROOF_CODE, PROOF_STATE


@unittest.skipUnless(os.name == 'posix', 'Bridge pipe/select lifecycle requires POSIX; not a Windows runtime test')
class BridgeExitTests(unittest.TestCase):
    def private_home(self, directory):
        home = Path(directory)
        os.chmod(home, 0o700)
        return home

    def test_timeout_is_nonzero(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            home = self.private_home(directory)
            self.assertEqual(run_bridge(True, home, timeout=0.3), 1)
            self.assertEqual(list(home.iterdir()), [])

    def test_failed_client_and_zero_without_callback_are_nonzero(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            home = self.private_home(directory)
            for code in (0, 7):
                command = [sys.executable, '-c', 'import sys; sys.exit(' + str(code) + ')']
                self.assertEqual(run_bridge(True, home, timeout=2, command=command), 1)

    def test_valid_synthetic_callback_is_zero(self):
        errors = []
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()) as output:
            home = self.private_home(directory)

            def callback_worker():
                fd = None
                try:
                    deadline = time.monotonic() + 4
                    while time.monotonic() < deadline:
                        runs = list(home.glob('oauth-*'))
                        if runs and (runs[0] / 'control.fifo').exists():
                            break
                        time.sleep(0.02)
                    else:
                        raise RuntimeError('synthetic FIFO was not created')
                    run = runs[0]
                    fd = os.open(run / 'control.fifo', os.O_RDONLY | os.O_NONBLOCK)
                    data = b''
                    while time.monotonic() < deadline and b'\n' not in data:
                        if select.select([fd], [], [], 0.1)[0]:
                            data += os.read(fd, 4096)
                            if not data:
                                time.sleep(0.02)
                    expected = json.loads(data)
                    self.assertEqual(expected['state'], PROOF_STATE)
                    callback = expected['redirect_uri'] + '?' + urlencode({'code': PROOF_CODE, 'state': PROOF_STATE})
                    out = os.open(run / 'callback.fifo', os.O_WRONLY | os.O_NONBLOCK)
                    try:
                        os.write(out, json.dumps({'callback_url': callback}).encode() + b'\n')
                    finally:
                        os.close(out)
                except Exception as error:
                    errors.append(type(error).__name__)
                finally:
                    if fd is not None:
                        os.close(fd)

            worker = threading.Thread(target=callback_worker, daemon=True)
            worker.start()
            result = run_bridge(True, home, timeout=5)
            worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(result, 0)
            self.assertIn('HARMLESS_BRIDGE_PROOF_VERIFIED', output.getvalue())
            self.assertEqual(list(home.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
