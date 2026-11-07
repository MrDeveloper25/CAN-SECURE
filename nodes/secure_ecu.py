import can

from core import config
from core.crypto import CryptoManager
from core.frame_codec import FrameCodec
from core.reassembler import FrameReassembler
from core.replay_guard import ReplayGuard
from core.failure_policy import FailurePolicy


class SecureECU:
    """Nodo que envia y recibe tramas autenticadas con el esquema CAN-Secure."""

    def __init__(self, channel=config.BUS_CHANNEL, interface=config.BUS_INTERFACE,
                 secret_key=config.DEFAULT_SECRET_KEY):
        self.bus = can.Bus(channel=channel, interface=interface,
                           fd=config.BUS_FD, receive_own_messages=False)
        self.crypto = CryptoManager(secret_key)
        self.reassembler = FrameReassembler()
        self.replay_guard = ReplayGuard()
        self.failure_policy = FailurePolicy()
        self.seq_counter = 0

    # ------------------------------------------------------------------ envio
    def send_secure_frame(self, base_id: int, data: bytes):
        """Envia un mensaje protegido como dos tramas CAN-FD (datos + auth)."""
        self.seq_counter += 1
        payload_to_sign = data + self.seq_counter.to_bytes(config.SEQ_COUNTER_BYTES, "big")
        mac = self.crypto.generate_mac(payload_to_sign)

        # Frame 1: datos reales.
        self.bus.send(can.Message(arbitration_id=base_id, data=data, is_fd=config.BUS_FD))
        # Frame 2: MAC + contador de secuencia.
        auth_bytes = FrameCodec.pack_auth_frame(mac, self.seq_counter)
        self.bus.send(can.Message(arbitration_id=config.auth_id_for(base_id),
                                  data=auth_bytes, is_fd=config.BUS_FD))

        print(f"[ECU Sent] ID: {hex(base_id)} | Seq: {self.seq_counter}")

    # ------------------------------------------------------------- recepcion
    def receive_and_verify(self, timeout=1.0):
        """Recibe tramas hasta reensamblar un par datos+auth y lo valida.

        Devuelve el payload si es legitimo, o None si se rechaza (replay, MAC
        invalido, o timeout sin trama completa).
        """
        msg = self.bus.recv(timeout)
        if msg is None:
            return None

        assembled = self.reassembler.feed(msg.arbitration_id, bytes(msg.data), msg.timestamp)
        if assembled is None:
            return None  # todavia falta el par; el llamador puede reintentar.

        return self._validate(assembled)

    def _validate(self, assembled):
        base_id = assembled.base_id
        try:
            mac, seq_counter = FrameCodec.unpack_auth_frame(assembled.auth_payload)
        except ValueError:
            self.failure_policy.register_failure(base_id)
            return None

        if not self.replay_guard.is_valid_sequence(base_id, seq_counter):
            self.failure_policy.register_failure(base_id)
            return None

        payload_to_sign = assembled.data + seq_counter.to_bytes(config.SEQ_COUNTER_BYTES, "big")
        if not self.crypto.verify_mac(payload_to_sign, mac):
            self.failure_policy.register_failure(base_id)
            return None

        self.failure_policy.reset_failures(base_id)
        return assembled.data

    def shutdown(self):
        self.bus.shutdown()
