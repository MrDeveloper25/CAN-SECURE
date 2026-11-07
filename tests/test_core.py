"""Tests unitarios de la logica central (no requieren bus CAN).

Ejecutar desde la raiz:   python -m pytest        (o)   python -m unittest
"""

import unittest

from core import config
from core.crypto import CryptoManager
from core.frame_codec import FrameCodec
from core.replay_guard import ReplayGuard
from core.failure_policy import FailurePolicy
from core.reassembler import FrameReassembler


class TestCrypto(unittest.TestCase):
    def test_mac_verifies(self):
        c = CryptoManager(b"k")
        mac = c.generate_mac(b"data")
        self.assertTrue(c.verify_mac(b"data", mac))

    def test_tampered_data_fails(self):
        c = CryptoManager(b"k")
        mac = c.generate_mac(b"data")
        self.assertFalse(c.verify_mac(b"DATA", mac))

    def test_mac_length_configurable(self):
        self.assertEqual(len(CryptoManager(b"k", mac_length=8).generate_mac(b"x")), 8)


class TestFrameCodec(unittest.TestCase):
    def test_roundtrip(self):
        mac = CryptoManager(b"k").generate_mac(b"x")
        packed = FrameCodec.pack_auth_frame(mac, 42)
        out_mac, seq = FrameCodec.unpack_auth_frame(packed)
        self.assertEqual((out_mac, seq), (mac, 42))

    def test_short_payload_raises(self):
        with self.assertRaises(ValueError):
            FrameCodec.unpack_auth_frame(b"\x00")


class TestReplayGuard(unittest.TestCase):
    def test_rejects_old_counter(self):
        g = ReplayGuard()
        self.assertTrue(g.is_valid_sequence(0x100, 5))
        self.assertFalse(g.is_valid_sequence(0x100, 5))  # igual -> replay
        self.assertFalse(g.is_valid_sequence(0x100, 3))  # menor -> replay
        self.assertTrue(g.is_valid_sequence(0x100, 6))   # mayor -> ok


class TestFailurePolicy(unittest.TestCase):
    def test_alert_after_threshold(self):
        p = FailurePolicy(max_failures=3)
        self.assertFalse(p.register_failure(0x100))
        self.assertFalse(p.register_failure(0x100))
        self.assertTrue(p.register_failure(0x100))  # 3er fallo -> alerta


class TestReassembler(unittest.TestCase):
    def test_pairs_regardless_of_order(self):
        r = FrameReassembler()
        self.assertIsNone(r.feed(config.auth_id_for(0x100), b"auth", 0.0))  # auth primero
        res = r.feed(0x100, b"data", 0.0)
        self.assertIsNotNone(res)
        self.assertEqual((res.base_id, res.data, res.auth_payload), (0x100, b"data", b"auth"))

    def test_orphan_data_frame(self):
        r = FrameReassembler(timeout=0.0)
        r.feed(0x100, b"solo", 0.0)
        orphans = r.collect_orphans(now=1.0)
        self.assertEqual(orphans, [(0x100, b"solo")])


if __name__ == "__main__":
    unittest.main()
