import unittest
import json

import app
from model.classifier import classify, score_url_and_text
from services.threat_intel import check_lists

class ClassifierTests(unittest.TestCase):
    def test_score_url_and_text_safe(self):
        score, explanation = score_url_and_text('https://example.com', 'Hello there')
        self.assertLess(score, 0.7)
        self.assertIn('No strong phishing indicators', explanation)

    def test_score_url_and_text_phishing(self):
        score, explanation = score_url_and_text('http://fake-login.top', 'Your account is suspended, verify password now')
        self.assertGreaterEqual(score, 0.7)
        self.assertIn('Suspicious TLD', explanation)
        self.assertIn('Contains phishing-like urgent words', explanation)

    def test_classify_returns_phishing_label(self):
        result = classify('http://malicious-vote.xyz', 'Please verify your password')
        self.assertEqual(result['label'], 'phishing')
        self.assertEqual(result['score'], 1.0)

class ThreatIntelTests(unittest.TestCase):
    def test_check_lists_blacklisted(self):
        result = check_lists('http://malicious-vote.xyz')
        self.assertTrue(result['blacklisted'])
        self.assertFalse(result['whitelisted'])

    def test_check_lists_whitelisted(self):
        result = check_lists('https://official-vote.university.edu')
        self.assertFalse(result['blacklisted'])
        self.assertTrue(result['whitelisted'])

    def test_check_lists_unknown(self):
        result = check_lists('https://example.com')
        self.assertFalse(result['blacklisted'])
        self.assertFalse(result['whitelisted'])

class AppTests(unittest.TestCase):
    def setUp(self):
        self.client = app.app.test_client()
        self.client.testing = True

    def test_health_endpoint(self):
        response = self.client.get('/health')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {'status': 'ok'})

    def test_index_get(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'PhishGuard AI', response.data)

    def test_scan_url_api(self):
        response = self.client.post('/scan-url',
                                    data=json.dumps({'url': 'http://example.com'}),
                                    content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['url'], 'http://example.com')
        self.assertIn('decision', data)

if __name__ == '__main__':
    unittest.main()
