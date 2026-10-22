import struct
from core.crypto import AES_GCM_NONCE_SIZE, AES_GCM_TAG_SIZE

class FrameCodec:
    @staticmethod
    def pack_auth_frame(nonce: bytes, tag: bytes, seq_counter: int) -> bytes:
        """Empaqueta nonce (12), tag GCM (16) y contador (4): 32 bytes."""
        if len(nonce) != AES_GCM_NONCE_SIZE or len(tag) != AES_GCM_TAG_SIZE:
            raise ValueError("Nonce o tag AES-GCM de longitud invalida.")
        if not 0 <= seq_counter <= 0xFFFFFFFF:
            raise ValueError("El contador debe caber en 32 bits.")
        return nonce + tag + struct.pack(">I", seq_counter)

    @staticmethod
    def unpack_auth_frame(auth_payload: bytes) -> tuple[bytes, bytes, int]:
        """Desempaqueta nonce, tag GCM y contador del Frame 2."""
        expected_size = AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE + 4
        if len(auth_payload) != expected_size:
            raise ValueError("Payload de autenticacion con longitud invalida.")

        nonce = auth_payload[:AES_GCM_NONCE_SIZE]
        tag_start = AES_GCM_NONCE_SIZE
        tag = auth_payload[tag_start:tag_start + AES_GCM_TAG_SIZE]
        seq_counter = struct.unpack(">I", auth_payload[-4:])[0]
        return nonce, tag, seq_counter

    @staticmethod
    def associated_data(base_id: int, seq_counter: int) -> bytes:
        """Vincula la autenticacion al ID CAN y al contador, sin cifrarlos."""
        return struct.pack(">II", base_id, seq_counter)