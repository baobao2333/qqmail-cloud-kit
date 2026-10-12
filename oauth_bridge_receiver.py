#!/usr/bin/env python3
"""Optional one-shot POSIX loopback receiver; callback data stays in private IPC."""
import argparse
import hmac
import json
import os
from pathlib import Path
import secrets
import select
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit
from oauth_bridge_common import (
    PORT, MIN_STATE_LENGTH, plain_value, unique_query, validate_callback,
    validate_redirect, verify_private_fifo, verify_private_directory, require_posix,
)

FORM_ORIGIN = f'http://127.0.0.1:{PORT}'


class CallbackHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def page(self, code, body, form=False):
        body = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'same-origin' if form else 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def static_page(self, code, message):
        self.page(code, '<!doctype html><meta charset=utf-8><title>QQ Mail authorization</title><h1>' + message + '</h1><p>You can return to your terminal.</p>')

    def private_form(self):
        self.page(200, '<!doctype html><html lang=zh-CN><meta charset=utf-8><title>QQ 邮箱 CLI 私密接收窗口</title>'
                  '<h1>QQ 邮箱 CLI 私密接收窗口</h1>'
                  '<p>这是你自己的 CLI 接收窗口，不是腾讯网站。</p>'
                  '<p>仅用于本次授权。请亲自在腾讯页面授权，复制地址栏完整返回网址，在这里粘贴并提交。</p>'
                  '<p>不要把返回网址发到聊天里，不要填写密码、短信验证码或账号信息。回调只交给本次官方 CLI，不写入普通文件或日志。</p>'
                  '<form method=post action=/qqmail-cli-submit autocomplete=off>'
                  '<input type=hidden name=csrf value="' + self.server.csrf_nonce + '">'
                  '<label for=callback_url>完整返回网址（输入隐藏）</label><br>'
                  '<input id=callback_url name=callback_url type=password autocomplete=off autocapitalize=none spellcheck=false maxlength=8192 size=70 required>'
                  '<p><button type=submit>仅提交给本次 QQ 邮箱登录</button></p></form></html>', form=True)

    def do_POST(self):
        stage = 'route'
        try:
            if self.path != '/qqmail-cli-submit' or self.server.consumed:
                raise ValueError('Unexpected form route')
            stage = 'host'
            if self.headers.get_all('Host', []) != [f'127.0.0.1:{PORT}']:
                raise ValueError('Unexpected form host')
            stage = 'origin'
            if self.headers.get_all('Origin', []) != [FORM_ORIGIN]:
                raise ValueError('Unexpected form origin')
            stage = 'encoding'
            types = self.headers.get_all('Content-Type', [])
            lengths = self.headers.get_all('Content-Length', [])
            if self.headers.get_all('Transfer-Encoding', []) or len(types) != 1 or types[0].split(';')[0].strip().lower() != 'application/x-www-form-urlencoded' or len(lengths) != 1:
                raise ValueError('Unexpected form encoding')
            length = int(lengths[0])
            if not 0 < length <= 65536:
                raise ValueError('Unexpected form length')
            self.connection.settimeout(10)
            stage = 'private_fields'
            data = self.rfile.read(length)
            if len(data) != length:
                raise ValueError('Incomplete form')
            fields = unique_query(data.decode('utf-8'))
            stage = 'csrf'
            if set(fields) != {'csrf', 'callback_url'} or not plain_value(fields['csrf'], 256) or not hmac.compare_digest(fields['csrf'], self.server.csrf_nonce):
                raise ValueError('Unexpected form nonce')
            stage = 'callback_validation'
            value = fields['callback_url']
            if not 0 < len(value) <= 8192 or not all(32 < ord(c) < 127 for c in value):
                raise ValueError('Invalid private callback value')
            parsed = urlsplit(value)
            redirect = validate_redirect(self.server.expected['redirect_uri'])
            if parsed.scheme != redirect.scheme or parsed.netloc != redirect.netloc or parsed.fragment or parsed.username or parsed.password:
                raise ValueError('Unexpected private callback destination')
            canonical = validate_callback(parsed.path + ('?' + parsed.query if parsed.query else ''), parsed.netloc, self.server.expected)
            if canonical != value:
                raise ValueError('Unexpected private callback encoding')
        except Exception:
            print('PRIVATE_FORM_REJECTED_STAGE', stage, flush=True)
            self.static_page(400, 'This private form submission was not accepted')
            return
        self.deliver_callback(value)

    def do_GET(self):
        if self.path == '/handoff' and not self.server.consumed:
            if self.headers.get_all('Host', []) != [f'127.0.0.1:{PORT}']:
                self.static_page(400, 'This local form address was not accepted')
                return
            self.private_form()
            return
        if self.path == '/qqmail-authorization-complete' and self.server.consumed:
            self.static_page(200 if self.server.delivered else 410, 'QQ Mail authorization received' if self.server.delivered else 'This session has expired')
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        if self.server.consumed:
            self.static_page(409, 'This authorization callback is already closed')
            return
        try:
            hosts = self.headers.get_all('Host', [])
            if len(hosts) != 1:
                raise ValueError('Unexpected host headers')
            value = validate_callback(self.path, hosts[0], self.server.expected)
        except Exception:
            self.static_page(400, 'This callback was not accepted')
            return
        self.deliver_callback(value)

    def deliver_callback(self, value):
        try:
            verify_private_fifo(self.server.callback_fifo)
            out = os.open(self.server.callback_fifo, os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            try:
                packet = json.dumps({'callback_url': value}, separators=(',', ':')).encode('utf-8') + b'\n'
                while packet:
                    count = os.write(out, packet)
                    if count <= 0:
                        raise RuntimeError('Private delivery failed')
                    packet = packet[count:]
            finally:
                os.close(out)
        except Exception:
            self.finish_callback(False)
            return
        self.finish_callback(True)

    def finish_callback(self, delivered):
        self.server.consumed = True
        self.server.delivered = delivered
        self.send_response(303)
        self.send_header('Location', '/qqmail-authorization-complete')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Length', '0')
        self.end_headers()
        print('CALLBACK_FORWARDED_PRIVATELY' if delivered else 'CALLBACK_SESSION_UNAVAILABLE', flush=True)
        timer = threading.Timer(5, self.server.shutdown)
        timer.daemon = True
        timer.start()


class QuietServer(HTTPServer):
    def handle_error(self, request, client_address):
        print('CALLBACK_RECEIVER_REQUEST_FAILED', flush=True)


def read_control(path, timeout):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    data = b''
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            if select.select([fd], [], [], 0.2)[0]:
                part = os.read(fd, 4096)
                if part:
                    data += part
                    if len(data) > 8192:
                        raise ValueError('Invalid private control data')
                    if b'\n' in data:
                        break
                else:
                    time.sleep(0.05)
        else:
            raise TimeoutError('Private control input timed out')
    finally:
        os.close(fd)
    expected = json.loads(data.decode('utf-8'))
    if set(expected) != {'state', 'redirect_uri'} or not plain_value(expected['state'], 1024, MIN_STATE_LENGTH):
        raise ValueError('Invalid control fields')
    validate_redirect(expected['redirect_uri'])
    return expected


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_directory')
    parser.add_argument('--timeout', type=int, default=600)
    args = parser.parse_args(argv)
    if not 1 <= args.timeout <= 600:
        parser.error('timeout must be between 1 and 600')
    server = None
    try:
        require_posix()
        home = Path(os.environ.get('QQMAIL_CODEX_HOME', str(Path.home() / '.codex-qqmail'))).expanduser().absolute()
        verify_private_directory(home)
        run = Path(args.run_directory).absolute()
        if run.parent != home or not run.name.startswith('oauth-'):
            raise ValueError('Unexpected private run directory')
        verify_private_directory(run)
        for name in ('control.fifo', 'callback.fifo'):
            verify_private_fifo(run / name)
        print('CALLBACK_RECEIVER_WAITING_FOR_CONFIGURATION', flush=True)
        expected = read_control(run / 'control.fifo', args.timeout)
        server = QuietServer(('127.0.0.1', PORT), CallbackHandler)
        server.expected = expected
        server.callback_fifo = run / 'callback.fifo'
        server.csrf_nonce = secrets.token_urlsafe(32)
        server.consumed = False
        server.delivered = False
        timer = threading.Timer(args.timeout, server.shutdown)
        timer.daemon = True
        timer.start()
        print('CALLBACK_RECEIVER_READY', flush=True)
        server.serve_forever()
        timer.cancel()
        return 0 if server.delivered else 1
    except (ValueError, RuntimeError, OSError, TimeoutError, KeyError, TypeError):
        print('CALLBACK_RECEIVER_START_FAILED: check POSIX, private FIFO, timeout and port availability', file=sys.stderr)
        return 2
    finally:
        if server is not None:
            server.server_close()
            print('CALLBACK_RECEIVER_STOPPED', flush=True)


if __name__ == '__main__':
    raise SystemExit(main())
