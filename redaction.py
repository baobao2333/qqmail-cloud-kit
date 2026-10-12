"""Best-effort secret filtering for MCP output; this is not a mail privacy filter."""
import html
import json
import re
from urllib.parse import unquote, urlsplit

REDACTED = '[redacted]'
REDACTED_URL = '[redacted sensitive URL]'
HIDDEN_KEYS = frozenset({
    'accesstoken', 'refreshtoken', 'idtoken', 'token', 'oauthtoken',
    'clientsecret', 'authorization', 'authorizationcode', 'code',
    'codeverifier', 'state', 'clientid', 'signature', 'sig', 'secret',
    'password', 'apikey', 'credential', 'credentials', 'sessiontoken',
    'authtoken', 'auth', 'clientassertion', 'sign', 'generateby',
    'xamzsignature', 'xgoogsignature',
})
COLON = r'(?::|&(?:amp;)*(?:#0*58|#x0*3a|colon);|%(?:25)*3a)'
SLASH = r'(?:/|&(?:amp;)*(?:#0*47|#x0*2f|sol);|%(?:25)*2f)'
URL_PATTERN = re.compile(rf'(?:https?{COLON})?{SLASH}{SLASH}[^\s<>"\x27`\\]+', re.IGNORECASE)
PARAMETER_PATTERN = re.compile(r'(?:[?&#;]|^)([^?&#;=\s]+)\s*=')
BEARER_PATTERN = re.compile(r'(?i)\bBearer\s+[^\s,<>"\x27}]+')
ASSIGNMENT_PATTERN = re.compile(r'(?i)\b([a-z][a-z0-9_%.-]*)\s*=\s*([^\s&<>"\x27]+)')


def decode_layers(value):
    # Bounded decoding also catches nested HTML entities and encoded parameter names.
    for _ in range(4):
        decoded = unquote(html.unescape(value))
        if decoded == value:
            return value
        value = decoded
    return value


def normalized_key(value):
    return re.sub(r'[^a-z]', '', decode_layers(str(value)).lower())


def sensitive_url(value):
    decoded = decode_layers(value)
    try:
        parsed = urlsplit(decoded)
        if parsed.username is not None or parsed.password is not None:
            return True
    except ValueError:
        return True
    # Inspect the whole decoded URL so secrets inside a nested return URL are covered.
    return any(normalized_key(match.group(1)) in HIDDEN_KEYS for match in PARAMETER_PATTERN.finditer(decoded))


def scrub(value, _depth=0):
    if _depth > 24:
        return '[omitted deeply nested content]'
    if isinstance(value, dict):
        return {k: REDACTED if normalized_key(k) in HIDDEN_KEYS and not (normalized_key(k) == 'code' and isinstance(v, (int, float)) and not isinstance(v, bool)) else scrub(v, _depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v, _depth + 1) for v in value]
    if not isinstance(value, str):
        return value
    if len(value) > 1_000_000:
        return '[omitted oversized content]'
    try:
        parsed = json.loads(value)
    except (ValueError, RecursionError):
        parsed = None
    if isinstance(parsed, (dict, list, str)):
        # MCP content.text often carries a second JSON layer.
        return json.dumps(scrub(parsed, _depth + 1), ensure_ascii=False)
    value = URL_PATTERN.sub(lambda match: REDACTED_URL if sensitive_url(match.group()) else match.group(), value)
    value = BEARER_PATTERN.sub('Bearer ' + REDACTED, value)
    return ASSIGNMENT_PATTERN.sub(lambda match: match.group(1) + '=' + REDACTED if normalized_key(match.group(1)) in HIDDEN_KEYS else match.group(), value)
