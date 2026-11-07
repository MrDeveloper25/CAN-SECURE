"""Escenario CON CAN-Secure: IDS activo verificando el frame dividido."""

import json
import threading
import time
from pathlib import Path

from nodes.ids_monitor import IDSMonitor
from nodes.secure_ecu import SecureECU
from eval import scenario

RESULTS_FILE = Path(__file__).resolve().parent.parent / "results" / "secure.json"


def run_secure_eval(write=True):
    print("--- INICIANDO ESCENARIO CAN-SECURE ---")
    ids = IDSMonitor()
    ecu = SecureECU()
    stop_event = threading.Event()
    result_box = {}

    def monitor():
        result_box["metrics"] = ids.start_monitoring(duration=8.0, stop_event=stop_event)

    t = threading.Thread(target=monitor)
    t.start()
    time.sleep(0.2)  # deja que el IDS empiece a escuchar.

    scenario.send_legit_traffic(ecu)
    scenario.run_attacks()

    time.sleep(0.5)       # drena el bus y vence el timeout de huerfanos.
    stop_event.set()
    t.join()
    ecu.shutdown()

    metrics = result_box.get("metrics", {})
    results = {
        "scenario": "secure",
        "legit_sent": scenario.LEGIT_FRAMES,
        "attack_types_total": len(scenario.ATTACK_TYPES),
        "ids_metrics": metrics,
    }
    if write:
        RESULTS_FILE.parent.mkdir(exist_ok=True)
        RESULTS_FILE.write_text(json.dumps(results, indent=2))
        print(f"[secure] Resultados guardados en {RESULTS_FILE}")
    return results


if __name__ == "__main__":
    res = run_secure_eval()
    print("[Secure Run Results]:", json.dumps(res, indent=2))
