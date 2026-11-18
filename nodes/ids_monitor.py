import time

import can
from cryptography.exceptions import InvalidTag

from core.crypto import DEMO_KEY
from core.frame_codec import AUTH_FRAME_TYPE, DATA_FRAME_TYPE, FrameCodec
from core.frame_reassembler import FrameAssemblyError, FrameReassembler
from core.key_manager import KeyManager
from core.replay_guard import ReplayGuard


class IDSMonitor:
    def __init__(
        self,
        channel="virtual_bus",
        interface="virtual",
        secret_key=DEMO_KEY,
        key_manager=None,
        base_ids=None,
        reassembly_timeout=1.0,
        replay_state_path=None,
    ):
        configured_ids = None if base_ids is None else FrameCodec.validate_base_ids(base_ids)
        self.base_ids = None if configured_ids is None else frozenset(configured_ids)
        self.reassembler = FrameReassembler(self.base_ids, timeout=reassembly_timeout)
        self.key_manager = key_manager if key_manager is not None else KeyManager(secret_key)
        self.replay_guard = ReplayGuard(replay_state_path)
        self.last_counters = self.replay_guard.last_counters

        self.metrics = {
            "total_frames": 0,
            "valid_frames": 0,
            "spoofing_detected": 0,
            "replay_detected": 0,
            "dos_alerts": 0,
        }

        self.msg_timestamps = []
        self.dos_threshold_per_sec = 50
        self.bus = can.interface.Bus(channel=channel, interface=interface, fd=True)

    def _check_dos_flood(self):
        now = time.monotonic()
        self.msg_timestamps.append(now)
        self.msg_timestamps = [timestamp for timestamp in self.msg_timestamps if now - timestamp <= 1.0]

        if len(self.msg_timestamps) > self.dos_threshold_per_sec:
            self.metrics["dos_alerts"] += 1
            print(f"[ALERTA IDS] ¡Ataque DoS Detectado! Tasa: {len(self.msg_timestamps)} msgs/seg")

    def _report_expired_frames(self):
        for base_id in self.reassembler.expire():
            self.metrics["spoofing_detected"] += 1
            print(f"[ALERTA IDS] Par CAN-Secure incompleto por timeout | ID: {hex(base_id)}")

    def start_monitoring(self, duration=10.0):
        if duration < 0:
            raise ValueError("La duracion del monitoreo no puede ser negativa.")
        print(f"[IDS] Sniffer iniciado en {self.bus.channel_info}... Escuchando tráfico.")
        deadline = time.monotonic() + duration

        while True:
            self._report_expired_frames()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            message = self.bus.recv(timeout=min(remaining, 0.5))
            if message is None:
                continue

            self.metrics["total_frames"] += 1
            self._check_dos_flood()

            if self.reassembler.reserved_ids is not None and message.arbitration_id not in self.reassembler.reserved_ids:
                continue

            self._report_expired_frames()
            try:
                assembled = self.reassembler.feed(
                    message.arbitration_id,
                    message.data,
                    is_fd=message.is_fd,
                    is_extended_id=message.is_extended_id,
                    is_remote_frame=message.is_remote_frame,
                    is_error_frame=message.is_error_frame,
                )
            except FrameAssemblyError as error:
                self.metrics["spoofing_detected"] += 1
                print(
                    f"[ALERTA IDS] Frame CAN-Secure invalido | "
                    f"ID: {hex(error.base_id if error.base_id is not None else message.arbitration_id)}"
                )
                continue

            if assembled is None:
                if (
                    message.data[:1] not in (
                        bytes((DATA_FRAME_TYPE,)),
                        bytes((AUTH_FRAME_TYPE,)),
                    )
                    and (
                        self.reassembler.reserved_ids is None
                        or message.arbitration_id in self.reassembler.reserved_ids
                    )
                ):
                    self.metrics["spoofing_detected"] += 1
                    print(f"[ALERTA IDS] Trama sin formato CAN-Secure | ID: {hex(message.arbitration_id)}")
                continue

            if not self.replay_guard.is_valid_sequence(assembled.base_id, assembled.seq_counter):
                last_seq = self.replay_guard.last_counters.get(assembled.base_id, -1)
                self.metrics["replay_detected"] += 1
                print(
                    f"[ALERTA IDS] ¡Replay Detectado! ID: {hex(assembled.base_id)} | "
                    f"Seq recibida: {assembled.seq_counter} <= Última válida: {last_seq}"
                )
                continue

            associated_data = FrameCodec.associated_data(assembled.base_id, assembled.seq_counter)
            try:
                self.key_manager.decrypt(
                    assembled.base_id,
                    assembled.ciphertext,
                    assembled.nonce,
                    assembled.tag,
                    associated_data,
                )
            except InvalidTag:
                self.metrics["spoofing_detected"] += 1
                print(f"[ALERTA IDS] ¡Spoofing/Tag AES-GCM inválido! ID: {hex(assembled.base_id)}")
                continue

            if not self.replay_guard.accept_sequence(assembled.base_id, assembled.seq_counter):
                self.metrics["replay_detected"] += 1
                continue
            self.last_counters = self.replay_guard.last_counters
            self.metrics["valid_frames"] += 1
            print(
                f"[IDS OK] Trama legítima verificada | ID: {hex(assembled.base_id)} | "
                f"Seq: {assembled.seq_counter}"
            )

        return self.metrics


if __name__ == "__main__":
    ids = IDSMonitor()
    results = ids.start_monitoring(duration=5.0)
    print("\n--- RESUMEN DE MÉTRICAS DEL IDS ---")
    print(results)
