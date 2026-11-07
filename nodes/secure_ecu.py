import can
from cryptography.exceptions import InvalidTag
from core.crypto import CryptoManager, DEMO_KEY
from core.frame_codec import FrameCodec
from core.replay_guard import ReplayGuard
from core.failure_policy import FailurePolicy
from core.key_manager import KeyManager

class SecureECU:
    
    def __init__(self, channel='virtual_bus', interface='virtual', secret_key=DEMO_KEY, key_manager=None):
        self.bus = can.interface.Bus(channel=channel, bustype=interface, fd=True)
        self.key_manager = (key_manager if key_manager is not None else KeyManager(secret_key))
        self.crypto = CryptoManager(self.key_manager.get_key())
        self.key_manager.register_crypto(self.crypto)
        self.replay_guard = ReplayGuard()
        self.failure_policy = FailurePolicy()
        self.seq_counter = 0   

    def send_secure_frame(self, base_id: int, data: bytes):
        if self.seq_counter >= 0xFFFFFFFF:
            raise OverflowError("El contador de secuencia AES-GCM se ha agotado.")
        self.seq_counter += 1
        associated_data = FrameCodec.associated_data(base_id, self.seq_counter)
        nonce, ciphertext, tag = self.crypto.encrypt(data, associated_data)
        
        # Frame 1: payload cifrado
        msg_data = can.Message(arbitration_id=base_id, data=ciphertext, is_fd=True)
        self.bus.send(msg_data)
        
        # Frame 2: nonce, tag de autenticacion y contador
        auth_bytes = FrameCodec.pack_auth_frame(nonce, tag, self.seq_counter)
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
            nonce, tag, seq_counter = FrameCodec.unpack_auth_frame(msg2.data)
        except Exception:
            self.failure_policy.register_failure(msg1.arbitration_id)
            return None

        if not self.replay_guard.is_valid_sequence(msg1.arbitration_id, seq_counter):
            self.failure_policy.register_failure(msg1.arbitration_id)
            return None

        associated_data = FrameCodec.associated_data(msg1.arbitration_id, seq_counter)
        try:
            plaintext = self.crypto.decrypt(msg1.data, nonce, tag, associated_data)
        except InvalidTag:
            self.failure_policy.register_failure(msg1.arbitration_id)
            return None

        self.replay_guard.accept_sequence(msg1.arbitration_id, seq_counter)
        self.failure_policy.reset_failures(msg1.arbitration_id)
        return plaintext