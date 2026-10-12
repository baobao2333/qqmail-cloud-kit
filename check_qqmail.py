#!/usr/bin/env python3
"""Read-only QQ Mail checks via official Codex 0.159.2 experimental app-server RPC.

No token file is opened. Runtime diagnostics are discarded. POSIX pipes are required.
Mail results remain personal data even after the best-effort secret filter.
"""
import argparse
import json
import math
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time
from oauth_bridge_common import verify_private_directory
from redaction import scrub

READ_TOOLS = frozenset({'GetMe', 'SearchMessages', 'GetMessage'})


def validate_arguments(value, schema):
    """Fail closed against the advertised primitive input schema."""
    props = schema.get('properties', {})
    if schema.get('type') != 'object' or not isinstance(props, dict):
        raise ValueError('Unsupported advertised input schema')
    if set(value) - set(props) or set(schema.get('required', [])) - set(value):
        raise ValueError('Unknown or missing argument keys')
    for key, val in value.items():
        rule = props[key]
        typ = rule.get('type')
        if typ == 'string':
            ok = isinstance(val, str) and len(val) <= min(8192, rule.get('maxLength', 8192)) and len(val) >= rule.get('minLength', 0)
            if ok and 'pattern' in rule:
                import re
                ok = re.search(rule['pattern'], val) is not None
        elif typ == 'integer':
            ok = isinstance(val, int) and not isinstance(val, bool)
        elif typ == 'number':
            ok = isinstance(val, (int, float)) and not isinstance(val, bool) and math.isfinite(val)
        elif typ == 'boolean':
            ok = isinstance(val, bool)
        else:
            raise ValueError('Unsupported advertised argument type')
        if not ok or ('enum' in rule and val not in rule['enum']):
            raise ValueError('Invalid argument value')
        if typ in {'integer', 'number'}:
            if val < rule.get('minimum', float('-inf')) or val > rule.get('maximum', float('inf')):
                raise ValueError('Argument out of advertised bounds')
    if 'limit' in value and (isinstance(value['limit'], bool) or not isinstance(value['limit'], int) or not 1 <= value['limit'] <= 50):
        raise ValueError('limit must be an integer between 1 and 50')


def load_arguments(home, argfile):
    request_root = home / 'requests'
    verify_private_directory(request_root)
    argfile = Path(argfile)
    if argfile.is_symlink() or argfile.resolve().parent != request_root.resolve() or argfile.suffix != '.json':
        raise ValueError('Arguments must be a regular JSON file in the dedicated requests directory')
    if not argfile.is_file() or argfile.stat().st_size > 32768:
        raise ValueError('Arguments file is missing or exceeds 32768 bytes')
    arguments = json.loads(argfile.read_text(encoding='utf-8'))
    if not isinstance(arguments, dict):
        raise ValueError('Arguments must be a JSON object')
    return arguments


class AppServer:
    def __init__(self, home):
        self.process = subprocess.Popen(
            [os.environ.get('CODEX_BIN', 'codex'), 'app-server', '--strict-config', '--stdio'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=home, env={**os.environ, 'CODEX_HOME': str(home), 'RUST_LOG': 'error', 'RUST_LOG_STYLE': 'never'},
            bufsize=0,
        )
        self.selector = selectors.DefaultSelector()
        for stream, label in ((self.process.stdout, 'response'), (self.process.stderr, 'diagnostic')):
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, label)
        self.request_id = 0
        self.buffer = b''

    def send(self, payload):
        self.process.stdin.write(json.dumps(payload).encode('utf-8') + b'\n')
        self.process.stdin.flush()

    def request(self, method, params):
        self.request_id += 1
        current = self.request_id
        self.send({'jsonrpc': '2.0', 'id': current, 'method': method, 'params': params})
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            while b'\n' in self.buffer:
                line, self.buffer = self.buffer.split(b'\n', 1)
                payload = json.loads(line)
                if payload.get('id') == current and ('result' in payload or 'error' in payload):
                    if 'error' in payload:
                        raise RuntimeError(json.dumps(scrub(payload['error']), ensure_ascii=False))
                    return payload['result']
                if 'method' in payload and 'id' in payload:
                    self.send({'jsonrpc': '2.0', 'id': payload['id'], 'error': {'code': -32601, 'message': 'Read-only QQ check does not accept interactive requests'}})
            for key, _ in self.selector.select(0.2):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    self.selector.unregister(key.fileobj)
                elif key.data == 'response':
                    self.buffer += chunk
                    if len(self.buffer) > 8 * 1024 * 1024:
                        raise RuntimeError('Official response exceeded the prototype size limit')
                # Runtime diagnostics are never echoed.
            if self.process.poll() is not None and not self.selector.get_map() and b'\n' not in self.buffer:
                raise RuntimeError('Official app-server exited before returning a result')
        raise TimeoutError('Official Codex request timed out')

    def close(self):
        self.selector.close()
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            stream.close()


def call_read_tool(client, thread_id, tools, name, arguments):
    if name not in READ_TOOLS or not isinstance(tools.get(name), dict):
        raise ValueError('The requested read-only tool was not advertised')
    validate_arguments(arguments, tools[name].get('inputSchema', {}))
    return client.request('mcpServer/tool/call', {'threadId': thread_id, 'server': 'qqmail', 'tool': name, 'arguments': arguments})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', nargs='?', default='status', choices=('status', 'tools', 'getme', 'readcheck', 'search', 'message'))
    parser.add_argument('arguments_file', nargs='?')
    args = parser.parse_args(argv)
    if os.name != 'posix':
        print('This prototype app-server helper requires POSIX pipes; Windows native is unsupported', file=sys.stderr)
        return 2
    client = None
    try:
        home = Path(os.environ.get('QQMAIL_CODEX_HOME', str(Path.home() / '.codex-qqmail'))).expanduser().absolute()
        verify_private_directory(home)
        if (args.mode in {'search', 'message'}) != bool(args.arguments_file):
            raise ValueError('search/message require one private arguments JSON file')
        arguments = load_arguments(home, args.arguments_file) if args.arguments_file else {}
        client = AppServer(home)
        client.request('initialize', {'clientInfo': {'name': 'qqmail_cloud_readonly_check', 'version': '0.1.0'}, 'capabilities': {'experimentalApi': True, 'explicitGatewayOauth': True}})
        client.send({'jsonrpc': '2.0', 'method': 'initialized', 'params': {}})
        status = client.request('mcpServerStatus/list', {'serverName': 'qqmail', 'detail': 'toolsAndAuthOnly'})
        server = next((item for item in status.get('data', []) if item.get('name') == 'qqmail'), None)
        if not server:
            raise RuntimeError('QQ Mail server was not returned by the official client')
        tools = server.get('tools', {})
        if args.mode == 'status':
            result = {'name': server.get('name'), 'authStatus': server.get('authStatus'), 'httpOrigin': server.get('httpOrigin'), 'tools': list(tools), 'toolsError': server.get('toolsError')}
        elif args.mode == 'tools':
            result = tools
        else:
            if server.get('toolsError'):
                raise RuntimeError(json.dumps(scrub(server['toolsError']), ensure_ascii=False))
            runtime = home / 'mail-runtime'
            runtime.mkdir(mode=0o700, exist_ok=True)
            verify_private_directory(runtime)
            if any(runtime.iterdir()):
                raise ValueError('mail-runtime must remain an empty dedicated MCP working directory')
            thread = client.request('thread/start', {'ephemeral': True, 'cwd': str(runtime), 'config': {'project_doc_max_bytes': 0}})
            thread_id = thread['thread']['id']
            if args.mode in {'search', 'message'}:
                name = 'SearchMessages' if args.mode == 'search' else 'GetMessage'
                result = call_read_tool(client, thread_id, tools, name, arguments)
            else:
                result = {'GetMe': call_read_tool(client, thread_id, tools, 'GetMe', {})}
                if args.mode == 'readcheck':
                    result['SearchMessages'] = call_read_tool(client, thread_id, tools, 'SearchMessages', {'dir': 'inbox', 'limit': 1})
        print(json.dumps(scrub(result), ensure_ascii=False, indent=2), flush=True)
        return 0
    except (OSError, ValueError, RuntimeError, TimeoutError, KeyError, TypeError):
        # Do not expose parser errors, exception context, request files, or raw runtime logs.
        print('QQMAIL_READ_CHECK_FAILED: verify the isolated home, CLI baseline, OAuth status and advertised schema', file=sys.stderr)
        return 1
    finally:
        if client is not None:
            client.close()


if __name__ == '__main__':
    raise SystemExit(main())
