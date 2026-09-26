import struct

class FrameCodec:
    @staticmethod
    def pack_auth_frame(mac: bytes, seq_counter: int) -> bytes:
        """Empaqueta el Frame 2 (MAC 32 bytes + Contador 4 bytes = 36 bytes)."""
        return mac + struct.pack(">I", seq_counter)

    @staticmethod
    def unpack_auth_frame(auth_payload: bytes):
        """Desempaqueta el MAC y el contador desde el Frame 2."""
        if len(auth_payload) < 36:
            raise ValueError("Payload de autenticación incompleto.")
        
        mac = auth_payload[:32]
        seq_counter = struct.unpack(">I", auth_payload[32:36])[0]
        return mac, seq_counter