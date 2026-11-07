"""Escenario SIN proteccion (linea base): una ECU legacy acepta todo.

Demuestra el "antes": sin CAN-Secure, toda trama inyectada (spoofing, replay,
flood) se acepta sin verificacion y no hay deteccion alguna.
"""

import json
import threading
import time
from pathlib import Path

import can

from core import config
from eval import scenario

RESULTS_FILE = Path(__file__).resolve().parent.parent / "results" / "baseline.json"


class LegacyECU:
    """ECU sin proteccion: acepta cualquier frame de datos sin validar."""

    def __init__(self):
        self.bus = can.Bus(channel=config.BUS_CHANNEL, interface=config.BUS_INTERFACE,
                           fd=config.BUS_FD, receive_own_messages=False)
        self.accepted_frames = 0

    def listen(self, duration, stop_event):
        start = time.time()
        while (time.time() - start) < duration:
            if stop_event.is_set():
                break
            msg = self.bus.recv(timeout=0.2)
            if msg is None:
                continue
            # Sin autenticacion: todo frame de datos (ID par) se "acepta".
            if not config.is_auth_id(msg.arbitration_id):
                self.accepted_frames += 1
        self.bus.shutdown()
        return self.accepted_frames


def run_baseline(write=True):
    print("--- INICIANDO ESCENARIO BASELINE (SIN PROTECCION) ---")
    ecu = LegacyECU()
    sender = can.Bus(channel=config.BUS_CHANNEL, interface=config.BUS_INTERFACE,
                     fd=config.BUS_FD, receive_own_messages=False)
    stop_event = threading.Event()
    box = {}

    def listener():
        box["accepted"] = ecu.listen(duration=8.0, stop_event=stop_event)

    t = threading.Thread(target=listener)
    t.start()
    time.sleep(0.2)

    # Trafico legitimo (sin firma, aqui es texto plano) + los mismos ataques.
    for i in range(scenario.LEGIT_FRAMES):
        sender.send(can.Message(arbitration_id=config.DATA_ID,
                                data=f"ENGINE_RPM_{3000 + i}".encode(), is_fd=config.BUS_FD))
        time.sleep(0.02)
    scenario.run_attacks()

    time.sleep(0.5)
    stop_event.set()
    t.join()
    sender.shutdown()

    accepted = box.get("accepted", 0)
    results = {
        "scenario": "baseline",
        "legit_sent": scenario.LEGIT_FRAMES,
        "attack_types_total": len(scenario.ATTACK_TYPES),
        "frames_accepted_without_verification": accepted,
        "attacks_detected": 0,  # una ECU legacy no detecta nada.
    }
    if write:
        RESULTS_FILE.parent.mkdir(exist_ok=True)
        RESULTS_FILE.write_text(json.dumps(results, indent=2))
        print(f"[baseline] Resultados guardados en {RESULTS_FILE}")
    print(f"[Baseline Result] Frames aceptados sin verificar: {accepted} | Deteccion: 0%")
    return results


if __name__ == "__main__":
    run_baseline()
