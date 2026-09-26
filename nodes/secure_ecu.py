import can
from core.crypto import CryptoManager
from core.frame_codec import FrameCodec
from core.replay_guard import ReplayGuard

class SecureECU:
    def __init__(self, channel='virtual_bus', interface='virtual', secret_key=b'secret_key_ecu1'):
        # Usamos bus 'virtual' de python-can para pruebas en Windows
        self.bus = can.interface.Bus(channel=channel, bustype=interface, fd=True)
        self.crypto = CryptoManager(secret_key)
        self.replay_guard = ReplayGuard()
        self.seq_counter = 0

    def send_secure_frame(self, base_id: int, data: bytes):
        self.seq_counter += 1
        
        # 1. Firmar payload + contador
        payload_to_sign = data + self.seq_counter.to_bytes(4, byteorder='big')
        mac = self.crypto.generate_mac(payload_to_sign)
        
        # 2. Enviar Frame 1 (Datos)
        msg_data = can.Message(arbitration_id=base_id, data=data, is_fd=True)
        self.bus.send(msg_data)
        
        # 3. Enviar Frame 2 (Autenticación)
        auth_bytes = FrameCodec.pack_auth_frame(mac, self.seq_counter)
        msg_auth = can.Message(arbitration_id=base_id + 1, data=auth_bytes, is_fd=True)
        self.bus.send(msg_auth)
        
        print(f"[ECU Sent] ID: {hex(base_id)} | Seq: {self.seq_counter}")