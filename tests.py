import unittest
from signature_engine import SignatureEngine
from ids_engine import IDS_Engine
import os

class TestSentinelle(unittest.TestCase):
    def setUp(self):
        self.sig_engine = SignatureEngine()

    def test_signature_detection(self):
        # Simulation d'un payload SQLi
        payload = b"SELECT * FROM users WHERE id=1 OR 1=1"
        match = self.sig_engine.inspect_payload(payload)
        self.assertIsNotNone(match)
        self.assertEqual(match['name'], "SQL Injection attempt")

    def test_signature_clean(self):
        # Payload innocent
        payload = b"GET /index.html HTTP/1.1"
        match = self.sig_engine.inspect_payload(payload)
        self.assertIsNone(match)

if __name__ == '__main__':
    unittest.main()
