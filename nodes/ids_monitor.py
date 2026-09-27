import can
import time
from core.crypto import CryptoManager
from core.frame_codec import FrameCodec

class IDSMonitor:
    def __init__(self, channel='virtual_bus', interface='virtual', secret_key=b'secret_key_ecu1'):
        self.bus = can.interface.Bus(channel=channel, bustype=interface, fd=True)
        self.crypto = CryptoManager(secret_key)
        self.last_counters = {}
        
        # Métricas de detección
        self.metrics = {
            "total_frames": 0,
            "valid_frames": 0,
            "spoofing_detected": 0,
            "replay_detected": 0,
            "dos_alerts": 0
        }

        # Control de frecuencia para DoS
        self.msg_timestamps = []
        self.dos_threshold_per_sec = 50  # Alerta si hay más de 50 mensajes/segundo

    def _check_dos_flood(self):
        """Verifica si la tasa de mensajes por segundo supera el umbral de DoS."""
        now = time.time()
        self.msg_timestamps.append(now)
        # Mantener solo los marcas de tiempo del último segundo
        self.msg_timestamps = [t for t in self.msg_timestamps if now - t <= 1.0]

        if len(self.msg_timestamps) > self.dos_threshold_per_sec:
            self.metrics["dos_alerts"] += 1
            print(f"[ALERTA IDS] ¡Ataque DoS Detectado! Tasa: {len(self.msg_timestamps)} msgs/seg")

    def start_monitoring(self, duration=10.0):
        """Monitorea la red CAN durante un tiempo definido."""
        print(f"[IDS] Sniffer iniciado en {self.bus.channel_info}... Escuchando tráfico.")
        start_time = time.time()

        while (time.time() - start_time) < duration:
            msg1 = self.bus.recv(timeout=0.5)
            if not msg1:
                continue

            self.metrics["total_frames"] += 1
            self._check_dos_flood()

            # Verificar si viene el par de Frame Dividido (Frame 2 de autenticación)
            msg2 = self.bus.recv(timeout=0.1)
            if not msg2 or msg2.arbitration_id != msg1.arbitration_id + 1:
                # Si no trae frame de autenticación, es una trama insegura / suplantada
                self.metrics["spoofing_detected"] += 1
                print(f"[ALERTA IDS] Trama sin autenticación detectada | ID: {hex(msg1.arbitration_id)}")
                continue

            try:
                mac, seq_counter = FrameCodec.unpack_auth_frame(msg2.data)
            except Exception:
                self.metrics["spoofing_detected"] += 1
                print(f"[ALERTA IDS] Frame de autenticación malformado | ID: {hex(msg2.arbitration_id)}")
                continue

            # 1. Verificación Anti-Replay
            last_seq = self.last_counters.get(msg1.arbitration_id, -1)
            if seq_counter <= last_seq:
                self.metrics["replay_detected"] += 1
                print(f"[ALERTA IDS] ¡Replay Detectado! ID: {hex(msg1.arbitration_id)} | Seq recibida: {seq_counter} <= Última válida: {last_seq}")
                continue

            # 2. Verificación de Autenticidad (HMAC)
            payload_to_sign = msg1.data + seq_counter.to_bytes(4, byteorder='big')
            if not self.crypto.verify_mac(payload_to_sign, mac):
                self.metrics["spoofing_detected"] += 1
                print(f"[ALERTA IDS] ¡Spoofing/Firma Inválida Detectada! ID: {hex(msg1.arbitration_id)}")
                continue

            # Si pasa todas las validaciones
            self.last_counters[msg1.arbitration_id] = seq_counter
            self.metrics["valid_frames"] += 1
            print(f"[IDS OK] Trama legítima verificada | ID: {hex(msg1.arbitration_id)} | Seq: {seq_counter}")

        return self.metrics

if __name__ == "__main__":
    # Prueba rápida ejecutando el IDS directamente
    ids = IDSMonitor()
    results = ids.start_monitoring(duration=5.0)
    print("\n--- RESUMEN DE MÉTRICAS DEL IDS ---")
    print(results)