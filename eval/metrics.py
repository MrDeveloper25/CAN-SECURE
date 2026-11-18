import json
import math
import statistics
from pathlib import Path


ATTACK_SCENARIOS = ("spoofing", "replay", "dos")


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * percentile) - 1)
    return round(ordered[index], 4)


def summarize_comparison(records: list[dict]) -> dict:
    modes = {}
    for mode in ("baseline", "secure"):
        mode_records = [record for record in records if record["mode"] == mode]
        attack_records = [
            record
            for record in mode_records
            if record["scenario"] in ATTACK_SCENARIOS
        ]
        detected = sum(bool(record["attack_detected"]) for record in attack_records)
        benign_records = [
            record for record in mode_records if record["scenario"] == "benign"
        ]
        benign_messages = sum(record["benign_messages"] for record in benign_records)
        false_positive_alerts = sum(
            record["false_positive_alerts"] for record in benign_records
        )
        accepted_values = [
            record["malicious_messages_accepted"]
            for record in attack_records
            if record["malicious_messages_accepted"] is not None
        ]
        modes[mode] = {
            "attack_events": len(attack_records),
            "detected_attack_events": detected,
            "attack_detection_rate_percent": round(
                100 * detected / len(attack_records), 2
            ) if attack_records else None,
            "malicious_frames_observed": sum(
                record["frames_observed"] for record in attack_records
            ),
            "malicious_messages_accepted": sum(accepted_values) if accepted_values else None,
            "benign_messages": benign_messages,
            "false_positive_alerts": false_positive_alerts,
            "false_positive_alerts_per_benign_message_percent": round(
                100 * false_positive_alerts / benign_messages, 2
            ) if benign_messages and mode == "secure" else None,
        }

    attack_scenarios = {}
    for scenario in ATTACK_SCENARIOS:
        secure_records = [
            record for record in records
            if record["mode"] == "secure" and record["scenario"] == scenario
        ]
        baseline_records = [
            record for record in records
            if record["mode"] == "baseline" and record["scenario"] == scenario
        ]
        detected = sum(bool(record["attack_detected"]) for record in secure_records)
        attack_scenarios[scenario] = {
            "events": len(secure_records),
            "detected_events": detected,
            "detection_rate_percent": round(
                100 * detected / len(secure_records), 2
            ) if secure_records else None,
            "malicious_messages_accepted": sum(
                record["malicious_messages_accepted"] or 0
                for record in secure_records
            ),
            "baseline_frames_observed": sum(
                record["frames_observed"] for record in baseline_records
            ),
        }

    baseline_benign = [
        record for record in records
        if record["mode"] == "baseline" and record["scenario"] == "benign"
    ]
    secure_benign = [
        record for record in records
        if record["mode"] == "secure" and record["scenario"] == "benign"
    ]
    baseline_frames = sum(record["frames_observed"] for record in baseline_benign)
    secure_frames = sum(record["frames_observed"] for record in secure_benign)
    baseline_bytes = sum(record["frame_payload_bytes"] for record in baseline_benign)
    secure_bytes = sum(record["frame_payload_bytes"] for record in secure_benign)
    baseline_latency = [
        sample for record in baseline_benign for sample in record["send_latency_ms"]
    ]
    secure_latency = [
        sample for record in secure_benign for sample in record["send_latency_ms"]
    ]

    return {
        "runs": len({record["run"] for record in records}),
        "modes": modes,
        "attack_scenarios": attack_scenarios,
        "scenario_execution_time_ms": {
            mode: round(sum(
                record["duration_ms"] for record in records
                if record["mode"] == mode
            ), 4)
            for mode in ("baseline", "secure")
        },
        "benign_traffic_overhead": {
            "baseline_frames": baseline_frames,
            "secure_frames": secure_frames,
            "frame_increase_percent": round(
                100 * (secure_frames - baseline_frames) / baseline_frames, 2
            ) if baseline_frames else None,
            "baseline_frame_payload_bytes": baseline_bytes,
            "secure_frame_payload_bytes": secure_bytes,
            "frame_payload_byte_increase_percent": round(
                100 * (secure_bytes - baseline_bytes) / baseline_bytes, 2
            ) if baseline_bytes else None,
            "note": "No incluye arbitraje, CRC, bit stuffing ni tiempos fisicos del bus.",
        },
        "benign_send_latency_ms": {
            "baseline_median": round(statistics.median(baseline_latency), 4) if baseline_latency else None,
            "baseline_p95": _percentile(baseline_latency, 0.95),
            "secure_median": round(statistics.median(secure_latency), 4) if secure_latency else None,
            "secure_p95": _percentile(secure_latency, 0.95),
            "note": "Tiempo local de preparar/enviar por python-can virtual; no es latencia CAN ni de ECU.",
        },
    }


def print_comparison_summary(summary: dict) -> None:
    print("\n================ COMPARACIÓN BASELINE / CAN-SECURE ================")
    for mode in ("baseline", "secure"):
        metrics = summary["modes"][mode]
        print(f"\n{mode.upper()}")
        print(
            f"Detección por evento: {metrics['detected_attack_events']}/"
            f"{metrics['attack_events']} "
            f"({metrics['attack_detection_rate_percent']}%)"
        )
        accepted = metrics["malicious_messages_accepted"]
        print(
            "Mensajes maliciosos aceptados: "
            f"{accepted if accepted is not None else 'N/A (baseline sin parser)'}"
        )
        print(f"Frames maliciosos observados: {metrics['malicious_frames_observed']}")
        print(
            f"Alertas falsas en benignos: {metrics['false_positive_alerts']}/"
            f"{metrics['benign_messages']} "
            f"({metrics['false_positive_alerts_per_benign_message_percent']}% alertas/mensaje)"
            if metrics["false_positive_alerts_per_benign_message_percent"] is not None
            else f"Alertas falsas en benignos: N/A (baseline no clasifica ataques)"
        )

    print("\nAtaques por escenario (CAN-Secure):")
    for scenario, metrics in summary["attack_scenarios"].items():
        print(
            f"  {scenario}: {metrics['detected_events']}/{metrics['events']} detectados "
            f"({metrics['detection_rate_percent']}%), "
            f"aceptados={metrics['malicious_messages_accepted']}; "
            f"frames baseline={metrics['baseline_frames_observed']}"
        )

    traffic = summary["benign_traffic_overhead"]
    print("\nTráfico benigno:")
    print(
        f"Frames: {traffic['baseline_frames']} -> {traffic['secure_frames']} "
        f"({traffic['frame_increase_percent']}% incremento)"
    )
    print(
        "Bytes de payload de frames: "
        f"{traffic['baseline_frame_payload_bytes']} -> "
        f"{traffic['secure_frame_payload_bytes']} "
        f"({traffic['frame_payload_byte_increase_percent']}% incremento)"
    )
    latency = summary["benign_send_latency_ms"]
    print(
        "Latencia local de envio mediana/p95 (ms): "
        f"baseline={latency['baseline_median']}/{latency['baseline_p95']}, "
        f"CAN-Secure={latency['secure_median']}/{latency['secure_p95']}"
    )
    execution = summary["scenario_execution_time_ms"]
    print(
        "Tiempo acumulado de escenarios (ms): "
        f"baseline={execution['baseline']}, CAN-Secure={execution['secure']}"
    )
    print("===================================================================")


def write_report(report: dict, output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
