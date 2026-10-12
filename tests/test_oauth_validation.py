"""Offline synthetic OAuth fixtures; no user account or callback data."""
import os
from pathlib import Path
import secrets
import sys
import tempfile
import unittest
from urllib.parse import urlencode
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from oauth_bridge_common import validate_authorization_url, validate_callback, verify_private_fifo


class OAuthValidationTests(unittest.TestCase):
    def setUp(self):
        self.state = secrets.token_urlsafe(32)
        self.redirect = 'http://127.0.0.1:14556/callback'
        self.expected = {'state': self.state, 'redirect_uri': self.redirect}

    def target(self, **changes):
        fields = {'code': 'SYNTHETIC_UNIT_TEST_ONLY', 'state': self.state}
        fields.update(changes)
        return '/callback?' + urlencode(fields)

    def authorization(self, **changes):
        fields = {'response_type': 'code', 'redirect_uri': self.redirect, 'scope': 'alias:read mail:read', 'state': self.state,
                  'code_challenge': secrets.token_urlsafe(32), 'code_challenge_method': 'S256'}
        fields.update(changes)
        return 'https://wx.mail.qq.com/oauth/authorize?' + urlencode(fields)

    def test_valid_callback(self):
        self.assertTrue(validate_callback(self.target(), '127.0.0.1:14556', self.expected).startswith(self.redirect + '?'))

    def test_wrong_state(self):
        with self.assertRaises(ValueError):
            validate_callback(self.target(state='SYNTHETIC_WRONG_STATE'), '127.0.0.1:14556', self.expected)

    def test_duplicate_parameter(self):
        with self.assertRaises(ValueError):
            validate_callback(self.target() + '&code=duplicate', '127.0.0.1:14556', self.expected)

    def test_wrong_host(self):
        with self.assertRaises(ValueError):
            validate_callback(self.target(), 'example.com:14556', self.expected)

    def test_wrong_path(self):
        with self.assertRaises(ValueError):
            validate_callback(self.target().replace('/callback?', '/other?'), '127.0.0.1:14556', self.expected)

    def test_fragment(self):
        with self.assertRaises(ValueError):
            validate_callback(self.target() + '#fragment', '127.0.0.1:14556', self.expected)

    def test_excessive_length(self):
        with self.assertRaises(ValueError):
            validate_callback(self.target(code='x' * 9000), '127.0.0.1:14556', self.expected)

    def test_wrong_issuer(self):
        with self.assertRaises(ValueError):
            validate_callback(self.target(iss='https://example.com'), '127.0.0.1:14556', self.expected)

    def test_malformed_percent(self):
        with self.assertRaises(ValueError):
            validate_callback(self.target() + '&iss=%ZZ', '127.0.0.1:14556', self.expected)

    def test_default_authorization_scopes(self):
        self.assertEqual(validate_authorization_url(self.authorization()), self.expected)

    def test_send_requires_explicit_flag(self):
        url = self.authorization(scope='alias:read mail:read mail:send')
        with self.assertRaises(ValueError):
            validate_authorization_url(url)
        self.assertEqual(validate_authorization_url(url, enable_send=True), self.expected)

    def test_delete_is_never_accepted(self):
        for enabled in (False, True):
            with self.assertRaises(ValueError):
                validate_authorization_url(self.authorization(scope='alias:read mail:read mail:send mail:delete'), enable_send=enabled)

    def test_duplicate_scope(self):
        with self.assertRaises(ValueError):
            validate_authorization_url(self.authorization(scope='alias:read mail:read mail:read'))

    def test_short_state(self):
        with self.assertRaises(ValueError):
            validate_authorization_url(self.authorization(state='x'))

    def test_invalid_challenge(self):
        for challenge in ('x', 'A' * 42, 'A' * 44, '+' * 43):
            with self.assertRaises(ValueError):
                validate_authorization_url(self.authorization(code_challenge=challenge))

    def test_wrong_authorization_endpoint(self):
        with self.assertRaises(ValueError):
            validate_authorization_url(self.authorization().replace('wx.mail.qq.com', 'example.com'))

    def test_duplicate_authorization_parameter(self):
        with self.assertRaises(ValueError):
            validate_authorization_url(self.authorization() + '&state=duplicate')

    def test_fixed_redirect_parameter_preserved(self):
        expected = {**self.expected, 'redirect_uri': self.redirect + '?fixed=synthetic'}
        value = validate_callback(self.target(fixed='synthetic'), '127.0.0.1:14556', expected)
        self.assertIn('fixed=synthetic', value)
        with self.assertRaises(ValueError):
            validate_callback(self.target(fixed='changed'), '127.0.0.1:14556', expected)

    @unittest.skipUnless(os.name == 'posix', 'POSIX FIFO and ownership APIs are unavailable on Windows native')
    def test_private_fifo(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            fifo = Path(directory) / 'callback.fifo'
            os.mkfifo(fifo, 0o600)
            verify_private_fifo(fifo)
            ordinary = Path(directory) / 'ordinary.txt'
            ordinary.write_text('synthetic regular file')
            with self.assertRaises(ValueError):
                verify_private_fifo(ordinary)
            os.chmod(fifo, 0o644)
            with self.assertRaises(ValueError):
                verify_private_fifo(fifo)


if __name__ == '__main__':
    unittest.main()
