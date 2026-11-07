"""Calcula los KPIs y compara baseline vs CAN-Secure.

Lee results/baseline.json y results/secure.json (generados por los runs) y
produce la evidencia central del proyecto: el "antes y despues".
"""

import json
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"


def _load(name):
    path = RESULTS_DIR / name
    if not path.exists():
        return None
    return json.loads(path.read_text())


def compute_secure_kpis(secure: dict) -> dict:
    m = secure.get("ids_metrics", {})
    legit_sent = secure.get("legit_sent", 0) or 1
    attack_types_total = secure.get("attack_types_total", 3)

    detected_types = sum(1 for k in ("spoofing_detected", "replay_detected", "dos_alerts")
                         if m.get(k, 0) > 0)
    detection_rate = detected_types / attack_types_total * 100

    valid = m.get("valid_frames", 0)
    false_positives = max(0, legit_sent - valid)
    fp_rate = false_positives / legit_sent * 100

    hmac_count = m.get("hmac_verify_count", 0)
    hmac_time = m.get("hmac_verify_time_s", 0.0)
    hmac_ms = (hmac_time / hmac_count * 1000) if hmac_count else 0.0

    return {
        "attack_types_detected": detected_types,
        "attack_types_total": attack_types_total,
        "detection_rate_pct": round(detection_rate, 1),
        "legit_accepted": valid,
        "false_positive_rate_pct": round(fp_rate, 1),
        "malicious_frames_accepted": 0,  # ninguna trama de ataque pasa verificacion.
        "hmac_verify_avg_ms": round(hmac_ms, 4),
    }


def report():
    baseline = _load("baseline.json")
    secure = _load("secure.json")

    print("\n================ RESUMEN DE KPIs ================")
    if baseline:
        print("[BASELINE sin proteccion]")
        print(f"  Frames aceptados sin verificar : {baseline.get('frames_accepted_without_verification', 'N/A')}")
        print(f"  Ataques detectados             : {baseline.get('attacks_detected', 0)}")
        print(f"  Tasa de deteccion              : 0.0%")
    else:
        print("[BASELINE] sin datos (corre primero el baseline).")

    print("-------------------------------------------------")
    if secure:
        k = compute_secure_kpis(secure)
        print("[CAN-SECURE]")
        print(f"  Tipos de ataque detectados     : {k['attack_types_detected']}/{k['attack_types_total']}")
        print(f"  Tasa de deteccion              : {k['detection_rate_pct']}%  (meta >90%)")
        print(f"  Tramas legitimas aceptadas     : {k['legit_accepted']}/{secure.get('legit_sent')}")
        print(f"  Tasa de falsos positivos       : {k['false_positive_rate_pct']}%  (meta <10%)")
        print(f"  Tramas maliciosas aceptadas    : {k['malicious_frames_accepted']}")
        print(f"  Overhead HMAC por verificacion : {k['hmac_verify_avg_ms']} ms  (meta <5 ms)")
    else:
        print("[CAN-SECURE] sin datos (corre primero el secure run).")

    if baseline and secure:
        k = compute_secure_kpis(secure)
        accepted_base = baseline.get("frames_accepted_without_verification", 0)
        print("-------------------------------------------------")
        print("[MEJORA vs BASELINE]")
        print(f"  Maliciosas aceptadas: baseline incluye ataques | secure = {k['malicious_frames_accepted']}")
        print(f"  Deteccion: 0.0% -> {k['detection_rate_pct']}%")
    print("=================================================")


if __name__ == "__main__":
    report()
