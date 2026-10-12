"""Synthetic secret/link regressions. No real mail, credentials or network."""
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from redaction import scrub, REDACTED, REDACTED_URL


class OutputScrubbingTests(unittest.TestCase):
    def test_whole_auth_url_removed(self):
        self.assertEqual(scrub('See https://example.com/private?refresh_token=SYNTHETIC_SECRET&generateby=SYNTHETIC_SIGNATURE now'), 'See ' + REDACTED_URL + ' now')

    def test_html_href(self):
        self.assertEqual(scrub('<a href="https://example.com/revoke?id_token=SYNTHETIC_SECRET">safe label</a>'), '<a href="' + REDACTED_URL + '">safe label</a>')

    def test_nested_html_entities(self):
        self.assertEqual(scrub('<a href="https://example.com/revoke?kind=test&amp;amp;refresh%5Ftoken=SYNTHETIC_SECRET">x</a>'), '<a href="' + REDACTED_URL + '">x</a>')

    def test_percent_encoded_name_and_value(self):
        self.assertEqual(scrub('https://example.com/cb?%69d_token=%53YNTHETIC_SECRET'), REDACTED_URL)

    def test_double_encoded_parameter(self):
        self.assertEqual(scrub('https://example.com/cb?%2569d_token=%2553YNTHETIC_SECRET'), REDACTED_URL)

    def test_signed_url_removed(self):
        self.assertEqual(scrub('https://example.com/file?X-Amz-Signature=SYNTHETIC_SECRET'), REDACTED_URL)

    def test_fragment_token(self):
        self.assertEqual(scrub('https://example.com/callback#access_token=SYNTHETIC_SECRET'), REDACTED_URL)

    def test_hash_route_token(self):
        self.assertEqual(scrub('https://example.com/#/callback?id_token=SYNTHETIC_SECRET'), REDACTED_URL)

    def test_ordinary_link_preserved(self):
        value = 'https://example.com/report?date=2026-01-01&page=2'
        self.assertEqual(scrub(value), value)

    def test_json_nested_in_mcp_text(self):
        text = json.dumps({'data': {'body': 'https://example.com/cb?code=SYNTHETIC_SECRET', 'access_token': 'SYNTHETIC_SECRET'}})
        value = {'content': [{'type': 'text', 'text': text}]}
        result = scrub(value)
        self.assertNotIn('SYNTHETIC_SECRET', json.dumps(result))
        self.assertEqual(json.loads(result['content'][0]['text'])['data']['access_token'], REDACTED)

    def test_double_json_text(self):
        value = json.dumps(json.dumps({'refresh_token': 'SYNTHETIC_SECRET'}))
        self.assertNotIn('SYNTHETIC_SECRET', scrub(value))

    def test_userinfo_removed(self):
        self.assertEqual(scrub('https://synthetic:synthetic@example.com/path'), REDACTED_URL)

    def test_protocol_relative_auth_url(self):
        self.assertEqual(scrub('<a href="//example.com/private?id_token=SYNTHETIC_SECRET">x</a>'), '<a href="' + REDACTED_URL + '">x</a>')

    def test_entity_scheme(self):
        for scheme in ('https&#58;//', 'https&amp;#58;//', 'https&colon;&sol;&sol;', 'https%3A%2F%2F'):
            value = '<a href="' + scheme + 'example.com/private?id_token=SYNTHETIC_SECRET">x</a>'
            self.assertEqual(scrub(value), '<a href="' + REDACTED_URL + '">x</a>')

    def test_nested_encoded_destination(self):
        self.assertEqual(scrub('https://example.com/redirect?next=https%3A%2F%2Fexample.com%2Fcb%3Faccess_token%3DSYNTHETIC_SECRET'), REDACTED_URL)

    def test_structured_token_variants(self):
        keys = ['token', 'secret', 'auth_token', 'id_token', 'client_assertion', 'generateby', 'x_goog_signature', 'refresh%5Ftoken']
        self.assertEqual(scrub({k: 'SYNTHETIC_SECRET' for k in keys}), {k: REDACTED for k in keys})

    def test_inline_id_token(self):
        self.assertEqual(scrub('id_token=SYNTHETIC_SECRET'), 'id_token=' + REDACTED)

    def test_plain_protocol_relative_link(self):
        self.assertEqual(scrub('//example.com/docs?page=2'), '//example.com/docs?page=2')

    def test_oversized_text_omitted(self):
        self.assertEqual(scrub('x' * 1_000_001), '[omitted oversized content]')

    def test_depth_bounded(self):
        value = 'SYNTHETIC_SECRET'
        for _ in range(30):
            value = [value]
        self.assertNotIn('SYNTHETIC_SECRET', str(scrub(value)))

    def test_bearer_removed(self):
        self.assertEqual(scrub('Bearer SYNTHETIC_SECRET'), 'Bearer ' + REDACTED)

    def test_error_codes_preserved(self):
        self.assertEqual(scrub({'code': -32000, 'message': 'https://example.com/cb?token=SYNTHETIC_SECRET'}), {'code': -32000, 'message': REDACTED_URL})


if __name__ == '__main__':
    unittest.main()
