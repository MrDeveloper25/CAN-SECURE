import can
from core.crypto import CryptoManager
from core.frame_codec import FrameCodec
from core.replay_guard import ReplayGuard
from core.failure_policy import FailurePolicy

class SecureECU:
    def __init__(self, channel='virtual_bus', interface='virtual', secret_key=b'secret_key_ecu1'):
        self.bus = can.interface.Bus(channel=channel, bustype=interface, fd=True)
        self.crypto = CryptoManager(secret_key)
        self.replay_guard = ReplayGuard()
        self.failure_policy = FailurePolicy()
        self.seq_counter = 0

    def send_secure_frame(self, base_id: int, data: bytes):
        self.seq_counter += 1
        payload_to_sign = data + self.seq_counter.to_bytes(4, byteorder='big')
        mac = self.crypto.generate_mac(payload_to_sign)
        
        # Frame 1: Datos
        msg_data = can.Message(arbitration_id=base_id, data=data, is_fd=True)
        self.bus.send(msg_data)
        
        # Frame 2: Autenticación
        auth_bytes = FrameCodec.pack_auth_frame(mac, self.seq_counter)
        msg_auth = can.Message(arbitration_id=base_id + 1, data=auth_bytes, is_fd=True)
        self.bus.send(msg_auth)
        
        print(f"[ECU Sent] ID: {hex(base_id)} | Seq: {self.seq_counter}")

    def receive_and_verify(self, timeout=1.0):
        msg1 = self.bus.recv(timeout)
        if not msg1:
            return None

        msg2 = self.bus.recv(timeout)
        if not msg2 or msg2.arbitration_id != msg1.arbitration_id + 1:
            self.failure_policy.register_failure(msg1.arbitration_id)
            return None

        try:
            mac, seq_counter = FrameCodec.unpack_auth_frame(msg2.data)
        except Exception:
            self.failure_policy.register_failure(msg1.arbitration_id)
            return None

        if not self.replay_guard.is_valid_sequence(msg1.arbitration_id, seq_counter):
            self.failure_policy.register_failure(msg1.arbitration_id)
            return None

        payload_to_sign = msg1.data + seq_counter.to_bytes(4, byteorder='big')
        if not self.crypto.verify_mac(payload_to_sign, mac):
            self.failure_policy.register_failure(msg1.arbitration_id)
            return None

        self.failure_policy.reset_failures(msg1.arbitration_id)
        return msg1.data