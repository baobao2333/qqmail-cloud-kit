import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import Mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from check_qqmail import call_read_tool, validate_arguments
from oauth_bridge_driver import cli_command
from prepare_home import create_home

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = {'type': 'object', 'properties': {'dir': {'type': 'string', 'enum': ['inbox']}, 'limit': {'type': 'integer', 'minimum': 1}}, 'required': ['dir']}


class ReadOnlyTests(unittest.TestCase):
    def test_example_defaults_are_readonly(self):
        config = tomllib.loads((ROOT / 'config.example.toml').read_text(encoding='utf-8'))
        self.assertEqual(set(config['mcp_servers']['qqmail']['scopes']), {'alias:read', 'mail:read'})
        self.assertEqual(set(config['mcp_servers']['qqmail']['enabled_tools']), {'GetMe', 'SearchMessages', 'GetMessage'})

    def test_cli_explicit_send(self):
        default = cli_command(False)
        enabled = cli_command(False, True)
        self.assertEqual(set(default[default.index('--scopes') + 1].split(',')), {'alias:read', 'mail:read'})
        self.assertEqual(set(enabled[enabled.index('--scopes') + 1].split(',')), {'alias:read', 'mail:read', 'mail:send'})
        self.assertNotIn('mail:delete', ' '.join(enabled))

    def test_schema_valid_arguments(self):
        validate_arguments({'dir': 'inbox', 'limit': 2}, SCHEMA)

    def test_empty_object_schema_for_getme(self):
        validate_arguments({}, {'type': 'object', 'additionalProperties': False})

    def test_schema_rejects_unknown_missing_enum_and_bool(self):
        for value in ({'extra': 'synthetic'}, {}, {'dir': 'other'}, {'dir': 'inbox', 'limit': True}):
            with self.assertRaises(ValueError):
                validate_arguments(value, SCHEMA)

    def test_limit_bound(self):
        for value in (0, 51, -1):
            with self.assertRaises(ValueError):
                validate_arguments({'dir': 'inbox', 'limit': value}, SCHEMA)

    def test_nonfinite_number_rejected(self):
        schema = {'type': 'object', 'properties': {'value': {'type': 'number'}}}
        with self.assertRaises(ValueError):
            validate_arguments({'value': float('nan')}, schema)

    def test_write_tool_never_called(self):
        client = Mock()
        for name in ('SendMessage', 'DeleteMessage'):
            with self.assertRaises(ValueError):
                call_read_tool(client, 'synthetic-thread', {name: {'inputSchema': SCHEMA}}, name, {'dir': 'inbox'})
        client.request.assert_not_called()

    def test_read_call_arguments_validated(self):
        client = Mock()
        with self.assertRaises(ValueError):
            call_read_tool(client, 'synthetic-thread', {'SearchMessages': {'inputSchema': SCHEMA}}, 'SearchMessages', {'dir': 'inbox', 'limit': 99})
        client.request.assert_not_called()

    def test_safe_import_has_no_runtime_side_effects(self):
        program = 'import oauth_bridge_driver, oauth_bridge_receiver, check_qqmail, prepare_home; print("SAFE_IMPORT")'
        result = subprocess.run([sys.executable, '-c', program], cwd=ROOT, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'SAFE_IMPORT')

    def test_invalid_home_exits_nonzero_without_traceback(self):
        with tempfile.TemporaryDirectory() as temp:
            env = {**os.environ, 'QQMAIL_CODEX_HOME': str(Path(temp) / 'missing'), 'PYTHONDONTWRITEBYTECODE': '1'}
            for script, args in (('oauth_bridge_driver.py', ['proof']), ('oauth_bridge_receiver.py', [str(Path(temp) / 'missing')]), ('check_qqmail.py', ['status'])):
                result = subprocess.run([sys.executable, str(ROOT / script), *args], env=env, capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('Traceback', result.stderr + result.stdout)

    @unittest.skipUnless(os.name == 'posix', '0700/0600 ownership checks require POSIX')
    def test_new_home_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / 'isolated'
            create_home(home)
            self.assertEqual(home.stat().st_mode & 0o777, 0o700)
            self.assertEqual((home / 'config.toml').stat().st_mode & 0o777, 0o600)
            before = (home / 'config.toml').read_bytes()
            with self.assertRaises(FileExistsError):
                create_home(home, True)
            self.assertEqual((home / 'config.toml').read_bytes(), before)
            send_home = Path(temp) / 'send-isolated'
            create_home(send_home, True)
            config = tomllib.loads((send_home / 'config.toml').read_text(encoding='utf-8'))
            self.assertIn('mail:send', config['mcp_servers']['qqmail']['scopes'])


if __name__ == '__main__':
    unittest.main()
