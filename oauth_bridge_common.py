"""Strict validation for the optional one-shot official QQ Mail OAuth bridge."""
import hmac
import os
import re
import stat
from urllib.parse import parse_qsl, urlsplit

OFFICIAL_AUTHORIZATION = 'https://wx.mail.qq.com/oauth/authorize'
OFFICIAL_ISSUER = 'https://wx.mail.qq.com'
OFFICIAL_RESOURCE = 'https://api.mail.qq.com/mcp'
READ_SCOPES = frozenset({'alias:read', 'mail:read'})
SCOPES = READ_SCOPES
PORT = 14556
MAX_CALLBACK_LENGTH = 8192
MIN_STATE_LENGTH = 16


def requested_scopes(enable_send=False):
    return READ_SCOPES | {'mail:send'} if enable_send else READ_SCOPES


def unique_query(query):
    if re.search(r'%(?![0-9A-Fa-f]{2})', query):
        raise ValueError('Malformed callback encoding')
    pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True, errors='strict')
    values = {}
    for key, value in pairs:
        if key in values:
            raise ValueError('Duplicate callback parameter')
        values[key] = value
    return values


def plain_value(value, maximum, minimum=1):
    return isinstance(value, str) and minimum <= len(value) <= maximum and all(32 <= ord(c) < 127 for c in value)


def validate_redirect(redirect):
    parsed = urlsplit(redirect)
    if parsed.scheme != 'http' or parsed.hostname not in {'localhost', '127.0.0.1'} or parsed.port != PORT:
        raise ValueError('Unexpected loopback redirect')
    if parsed.username or parsed.password or parsed.fragment or not re.fullmatch(r'/[A-Za-z0-9/_-]{1,256}', parsed.path):
        raise ValueError('Unexpected loopback redirect path')
    fixed = unique_query(parsed.query) if parsed.query else {}
    if set(fixed) & {'code', 'state', 'iss'}:
        raise ValueError('Unexpected fixed redirect parameters')
    return parsed


def validate_authorization_url(url, enable_send=False):
    parsed = urlsplit(url)
    if f'{parsed.scheme}://{parsed.netloc}{parsed.path}' != OFFICIAL_AUTHORIZATION or parsed.fragment:
        raise ValueError('Unexpected authorization endpoint')
    values = unique_query(parsed.query)
    if values.get('response_type') != 'code' or values.get('code_challenge_method') != 'S256':
        raise ValueError('Expected PKCE authorization-code flow')
    scopes = values.get('scope', '').split()
    if len(scopes) != len(set(scopes)) or set(scopes) != requested_scopes(enable_send):
        raise ValueError('Unexpected requested scope')
    if not plain_value(values.get('state'), 1024, MIN_STATE_LENGTH):
        raise ValueError('Missing authorization protection')
    if not re.fullmatch(r'[A-Za-z0-9_-]{43}', values.get('code_challenge', '')):
        raise ValueError('Invalid S256 challenge')
    if values.get('resource', OFFICIAL_RESOURCE) != OFFICIAL_RESOURCE:
        raise ValueError('Unexpected OAuth resource')
    redirect = values.get('redirect_uri', '')
    validate_redirect(redirect)
    return {'state': values['state'], 'redirect_uri': redirect}


def validate_callback(request_target, host, expected):
    if not isinstance(request_target, str) or not 0 < len(request_target) <= MAX_CALLBACK_LENGTH:
        raise ValueError('Invalid callback length')
    if not all(32 < ord(c) < 127 for c in request_target):
        raise ValueError('Invalid callback characters')
    if not plain_value(expected.get('state'), 1024, MIN_STATE_LENGTH):
        raise ValueError('Invalid expected state')
    redirect = validate_redirect(expected['redirect_uri'])
    parsed = urlsplit(request_target)
    if parsed.scheme or parsed.netloc or parsed.fragment or parsed.path != redirect.path or host != redirect.netloc:
        raise ValueError('Unexpected callback destination')
    values = unique_query(parsed.query)
    fixed = unique_query(redirect.query) if redirect.query else {}
    if not {'code', 'state'}.issubset(values) or set(values) - {'code', 'state', 'iss'} - set(fixed) or any(values.get(k) != v for k, v in fixed.items()):
        raise ValueError('Unexpected callback parameters')
    if not plain_value(values['code'], 4096) or not plain_value(values['state'], 1024, MIN_STATE_LENGTH):
        raise ValueError('Invalid callback values')
    if not hmac.compare_digest(values['state'], expected['state']):
        raise ValueError('OAuth state did not match')
    if 'iss' in values and values['iss'] != OFFICIAL_ISSUER:
        raise ValueError('Unexpected OAuth issuer')
    return f'{redirect.scheme}://{redirect.netloc}{redirect.path}?' + parsed.query


def require_posix():
    if os.name != 'posix' or not all(hasattr(os, name) for name in ('mkfifo', 'O_NOFOLLOW', 'getuid')):
        raise RuntimeError('This optional helper requires a POSIX environment; Windows native is unsupported')


def verify_private_directory(path):
    require_posix()
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
        raise ValueError('Expected an owner-only 0700 private directory')


def verify_private_fifo(path):
    require_posix()
    info = os.lstat(path)
    verify_private_directory(os.path.dirname(path))
    if not stat.S_ISFIFO(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid():
        raise ValueError('Unexpected private IPC file')
