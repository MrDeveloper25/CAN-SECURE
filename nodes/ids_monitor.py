import time

import can

from core import config
from core.crypto import CryptoManager
from core.frame_codec import FrameCodec
from core.reassembler import FrameReassembler


class IDSMonitor:
    """Sniffer que escucha el bus, reensambla el frame dividido y detecta
    spoofing (sin auth / MAC invalido), replay (contador reusado) y DoS (tasa)."""

    def __init__(self, channel=config.BUS_CHANNEL, interface=config.BUS_INTERFACE,
                 secret_key=config.DEFAULT_SECRET_KEY):
        self.bus = can.Bus(channel=channel, interface=interface,
                           fd=config.BUS_FD, receive_own_messages=False)
        self.crypto = CryptoManager(secret_key)
        self.reassembler = FrameReassembler()
        self.last_counters = {}
        self.dos_threshold_per_sec = config.DOS_THRESHOLD_PER_SEC
        self.msg_timestamps = []

        self.metrics = {
            "total_frames": 0,
            "valid_frames": 0,
            "spoofing_detected": 0,
            "replay_detected": 0,
            "dos_alerts": 0,
            "hmac_verify_count": 0,
            "hmac_verify_time_s": 0.0,
        }

    def _check_dos_flood(self, now):
        self.msg_timestamps.append(now)
        self.msg_timestamps = [t for t in self.msg_timestamps if now - t <= 1.0]
        if len(self.msg_timestamps) > self.dos_threshold_per_sec:
            self.metrics["dos_alerts"] += 1

    def _process_assembled(self, assembled):
        base_id = assembled.base_id
        try:
            mac, seq_counter = FrameCodec.unpack_auth_frame(assembled.auth_payload)
        except ValueError:
            self.metrics["spoofing_detected"] += 1
            print(f"[ALERTA IDS] Frame de autenticacion malformado | ID: {hex(base_id)}")
            return

        # Anti-replay: contador debe ser estrictamente mayor al ultimo valido.
        last_seq = self.last_counters.get(base_id, -1)
        if seq_counter <= last_seq:
            self.metrics["replay_detected"] += 1
            print(f"[ALERTA IDS] Replay detectado | ID: {hex(base_id)} | "
                  f"Seq {seq_counter} <= ultima {last_seq}")
            return

        # Autenticidad (HMAC) — se mide el tiempo como KPI de overhead.
        payload_to_sign = assembled.data + seq_counter.to_bytes(config.SEQ_COUNTER_BYTES, "big")
        t0 = time.perf_counter()
        ok = self.crypto.verify_mac(payload_to_sign, mac)
        self.metrics["hmac_verify_time_s"] += time.perf_counter() - t0
        self.metrics["hmac_verify_count"] += 1

        if not ok:
            self.metrics["spoofing_detected"] += 1
            print(f"[ALERTA IDS] Firma HMAC invalida (spoofing) | ID: {hex(base_id)}")
            return

        self.last_counters[base_id] = seq_counter
        self.metrics["valid_frames"] += 1
        print(f"[IDS OK] Trama legitima | ID: {hex(base_id)} | Seq: {seq_counter}")

    def start_monitoring(self, duration=10.0, stop_event=None):
        """Monitorea hasta agotar `duration` o hasta que se active `stop_event`."""
        print(f"[IDS] Sniffer iniciado en {self.bus.channel_info}...")
        start_time = time.time()

        while (time.time() - start_time) < duration:
            if stop_event is not None and stop_event.is_set():
                break

            msg = self.bus.recv(timeout=0.2)
            now = time.time()

            if msg is not None:
                self.metrics["total_frames"] += 1
                self._check_dos_flood(now)
                assembled = self.reassembler.feed(msg.arbitration_id, bytes(msg.data), msg.timestamp)
                if assembled is not None:
                    self._process_assembled(assembled)

            # Frames de datos sin su par de auth = inyeccion no autenticada.
            # Las tramas del flood DoS se contabilizan solo como DoS (por tasa),
            # no como spoofing, para no mezclar los KPIs.
            for base, _data in self.reassembler.collect_orphans(now):
                if base == config.DOS_FLOOD_ID:
                    continue
                self.metrics["spoofing_detected"] += 1
                print(f"[ALERTA IDS] Trama sin autenticacion (spoofing) | ID: {hex(base)}")

        self.bus.shutdown()
        return self.metrics


if __name__ == "__main__":
    ids = IDSMonitor()
    results = ids.start_monitoring(duration=5.0)
    print("\n--- RESUMEN DE METRICAS DEL IDS ---")
    print(results)
