import struct

from core import config


class FrameCodec:
    """Empaqueta/desempaqueta el Frame 2 (autenticacion) del esquema dividido.

    Frame 2 = MAC (config.MAC_LENGTH bytes) + contador de secuencia (uint32).
    """

    @staticmethod
    def pack_auth_frame(mac: bytes, seq_counter: int) -> bytes:
        """Empaqueta MAC + contador en el payload del Frame 2."""
        return mac + struct.pack(">I", seq_counter)

    @staticmethod
    def unpack_auth_frame(auth_payload: bytes, mac_length: int | None = None):
        """Desempaqueta MAC y contador desde el Frame 2.

        Lanza ValueError si el payload no tiene el tamano esperado
        (mac_length + SEQ_COUNTER_BYTES), lo que de por si marca una trama
        malformada / no conforme al estandar.
        """
        if mac_length is None:
            mac_length = config.MAC_LENGTH
        expected = mac_length + config.SEQ_COUNTER_BYTES
        if len(auth_payload) < expected:
            raise ValueError(
                f"Payload de autenticacion incompleto: {len(auth_payload)} < {expected} bytes."
            )
        mac = auth_payload[:mac_length]
        seq_counter = struct.unpack(">I", auth_payload[mac_length:expected])[0]
        return mac, seq_counter
