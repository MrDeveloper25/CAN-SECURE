import argparse
import contextlib
import io
import time
import uuid

import can

from attacks.dos_flood import run_dos_attack
from attacks.spoofing import run_spoofing_attack
from core.crypto import DEMO_KEY
from core.frame_codec import FrameCodec
from core.key_manager import KeyManager
from eval.metrics import print_comparison_summary, summarize_comparison, write_report
from nodes.ids_monitor import IDSMonitor
from nodes.secure_ecu import SecureECU

BASE_ID = 0x200
BENIGN_MESSAGES = 10
BENIGN_PAYLOAD = b"BENIGN_SENSOR_01"
REPLAY_PAYLOAD = b"CAPTURED_MESSAGE"


def _channel(run: int, mode: str, scenario: str) -> str:
    return f"can_secure_eval_{run}_{mode}_{scenario}_{uuid.uuid4().hex}"


def _secure_pair(base_id: int = BASE_ID, sequence: int = 1):
    associated_data = FrameCodec.associated_data(base_id, sequence)
    key_manager = KeyManager(DEMO_KEY)
    nonce, ciphertext, tag = key_manager.encrypt(
        base_id,
        REPLAY_PAYLOAD,
        associated_data,
    )
    return (
        can.Message(
            arbitration_id=base_id,
            data=FrameCodec.pack_data_frame(ciphertext, sequence),
            is_fd=True,
            is_extended_id=False,
        ),
        can.Message(
            arbitration_id=base_id + 1,
            data=FrameCodec.pack_auth_frame(
                nonce,
                tag,
                sequence,
                len(ciphertext),
            ),
            is_fd=True,
            is_extended_id=False,
        ),
    )


def _receive_available(bus, timeout: float = 0.1) -> list:
    received = []
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return received
        message = bus.recv(timeout=remaining)
        if message is None:
            return received
        received.append(message)


def _record(
    run: int,
    mode: str,
    scenario: str,
    detected: bool,
    accepted: int | None,
    frames_observed: int,
    frame_payload_bytes: int,
    latency_ms: list[float],
    *,
    benign_messages: int = 0,
    false_positive_alerts: int = 0,
) -> dict:
    return {
        "run": run,
        "mode": mode,
        "scenario": scenario,
        "attack_detected": detected,
        "malicious_messages_accepted": accepted,
        "frames_observed": frames_observed,
        "frame_payload_bytes": frame_payload_bytes,
        "send_latency_ms": latency_ms,
        "benign_messages": benign_messages,
        "false_positive_alerts": false_positive_alerts,
    }


def _run_baseline_spoofing(run: int) -> dict:
    channel = _channel(run, "baseline", "spoofing")
    receiver = can.interface.Bus(channel=channel, interface="virtual", fd=True)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            run_spoofing_attack(channel=channel, target_id=BASE_ID)
        received = _receive_available(receiver)
        return _record(run, "baseline", "spoofing", False, None, len(received),
                       sum(len(message.data) for message in received), [])
    finally:
        receiver.shutdown()


def _run_secure_spoofing(run: int) -> dict:
    channel = _channel(run, "secure", "spoofing")
    ids = IDSMonitor(channel=channel)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            run_spoofing_attack(channel=channel, target_id=BASE_ID)
            results = ids.start_monitoring(duration=0.1)
        detected = results["spoofing_detected"] > 0
        return _record(
            run, "secure", "spoofing", detected,
            results["valid_frames"], results["total_frames"],
            len(b"FAKE_SPEED_200KMH"), [],
        )
    finally:
        ids.bus.shutdown()


def _run_baseline_replay(run: int) -> dict:
    channel = _channel(run, "baseline", "replay")
    receiver = can.interface.Bus(channel=channel, interface="virtual", fd=True)
    injector = can.interface.Bus(channel=channel, interface="virtual", fd=True)
    frames = _secure_pair()
    try:
        for frame in frames + frames:
            injector.send(frame)
        received = _receive_available(receiver)
        return _record(
            run, "baseline", "replay", False, None, len(received),
            sum(len(message.data) for message in received), [],
        )
    finally:
        receiver.shutdown()
        injector.shutdown()


def _run_secure_replay(run: int) -> dict:
    channel = _channel(run, "secure", "replay")
    ids = IDSMonitor(channel=channel)
    injector = can.interface.Bus(channel=channel, interface="virtual", fd=True)
    frames = _secure_pair()
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            for frame in frames + frames:
                injector.send(can.Message(
                    arbitration_id=frame.arbitration_id,
                    data=frame.data,
                    is_fd=frame.is_fd,
                    is_extended_id=frame.is_extended_id,
                ))
            results = ids.start_monitoring(duration=0.1)
        detected = results["replay_detected"] > 0
        accepted = max(0, results["valid_frames"] - 1)
        return _record(
            run, "secure", "replay", detected, accepted,
            results["total_frames"], sum(len(frame.data) for frame in frames + frames), [],
        )
    finally:
        ids.bus.shutdown()
        injector.shutdown()


def _run_baseline_dos(run: int, dos_count: int) -> dict:
    channel = _channel(run, "baseline", "dos")
    receiver = can.interface.Bus(channel=channel, interface="virtual", fd=True)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            run_dos_attack(channel=channel, count=dos_count)
        received = _receive_available(receiver)
        return _record(
            run, "baseline", "dos", False, None, len(received),
            sum(len(message.data) for message in received), [],
        )
    finally:
        receiver.shutdown()


def _run_secure_dos(run: int, dos_count: int) -> dict:
    channel = _channel(run, "secure", "dos")
    ids = IDSMonitor(channel=channel)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            run_dos_attack(channel=channel, count=dos_count)
            results = ids.start_monitoring(duration=0.2)
        detected = results["dos_alerts"] > 0
        return _record(
            run, "secure", "dos", detected, results["valid_frames"],
            results["total_frames"], results["total_frames"] * 8, [],
        )
    finally:
        ids.bus.shutdown()


def _run_baseline_benign(run: int) -> dict:
    channel = _channel(run, "baseline", "benign")
    receiver = can.interface.Bus(channel=channel, interface="virtual", fd=True)
    sender = can.interface.Bus(channel=channel, interface="virtual", fd=True)
    latency_ms = []
    try:
        for _ in range(BENIGN_MESSAGES):
            message = can.Message(
                arbitration_id=BASE_ID,
                data=BENIGN_PAYLOAD,
                is_fd=True,
                is_extended_id=False,
            )
            started = time.perf_counter_ns()
            sender.send(message)
            latency_ms.append((time.perf_counter_ns() - started) / 1_000_000)
        received = _receive_available(receiver)
        return _record(
            run, "baseline", "benign", False, 0, len(received),
            sum(len(message.data) for message in received), latency_ms,
            benign_messages=len(received),
        )
    finally:
        receiver.shutdown()
        sender.shutdown()


def _run_secure_benign(run: int) -> dict:
    channel = _channel(run, "secure", "benign")
    key_manager = KeyManager(DEMO_KEY)
    ids = IDSMonitor(channel=channel, key_manager=key_manager)
    ecu = SecureECU(channel=channel, key_manager=key_manager)
    observer = can.interface.Bus(channel=channel, interface="virtual", fd=True)
    latency_ms = []
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            for _ in range(BENIGN_MESSAGES):
                started = time.perf_counter_ns()
                ecu.send_secure_frame(BASE_ID, BENIGN_PAYLOAD)
                latency_ms.append((time.perf_counter_ns() - started) / 1_000_000)
            results = ids.start_monitoring(duration=0.2)
        observed_frames = _receive_available(observer)
        false_positives = (
            results["spoofing_detected"]
            + results["replay_detected"]
            + results["dos_alerts"]
        )
        return _record(
            run, "secure", "benign", False, 0,
            results["total_frames"],
            sum(len(message.data) for message in observed_frames),
            latency_ms,
            benign_messages=len(observed_frames) // 2,
            false_positive_alerts=false_positives,
        )
    finally:
        ids.bus.shutdown()
        ecu.bus.shutdown()
        observer.shutdown()


def _print_progress(record: dict, run: int, total_runs: int, elapsed_ms: float) -> None:
    mode = record["mode"]
    scenario = record["scenario"]
    if scenario == "benign":
        messages = record["benign_messages"]
        expected_frames = BENIGN_MESSAGES * (2 if mode == "secure" else 1)
        passed = (
            messages == BENIGN_MESSAGES
            and record["frames_observed"] == expected_frames
            and (mode != "secure" or record["false_positive_alerts"] == 0)
        )
        status = "PASS" if passed else "FAIL"
        detail = (
            f"mensajes={messages}/{BENIGN_MESSAGES}, "
            f"frames={record['frames_observed']}/{expected_frames}"
        )
        if mode == "secure":
            detail += f", alertas={record['false_positive_alerts']}"
    elif mode == "baseline":
        status = "INFO"
        detail = f"frames observados={record['frames_observed']}, detección=N/A (sin parser)"
    else:
        passed = (
            record["attack_detected"]
            and record["malicious_messages_accepted"] == 0
        )
        status = "PASS" if passed else "FAIL"
        detail = (
            f"detectado={'sí' if record['attack_detected'] else 'no'}, "
            f"mensajes aceptados={record['malicious_messages_accepted']}"
        )
    print(
        f"[{status}] corrida {run}/{total_runs} {mode}/{scenario} | "
        f"{detail} | {elapsed_ms:.1f} ms",
        flush=True,
    )


def _run_scenario(run: int, total_runs: int, mode: str, scenario: str, runner, *args) -> dict:
    started_at = time.perf_counter()
    record = runner(run, *args)
    elapsed_ms = (time.perf_counter() - started_at) * 1000
    record["duration_ms"] = round(elapsed_ms, 4)
    _print_progress(record, run, total_runs, elapsed_ms)
    return record


def run_comparison(runs: int = 3, dos_count: int = 100) -> dict:
    if isinstance(runs, bool) or not isinstance(runs, int) or runs < 1:
        raise ValueError("El numero de corridas debe ser un entero positivo.")
    if (
        isinstance(dos_count, bool)
        or not isinstance(dos_count, int)
        or dos_count < 51
    ):
        raise ValueError("El conteo DoS debe ser al menos 51 para superar el umbral del IDS.")

    records = []
    for run in range(1, runs + 1):
        records.extend((
            _run_scenario(run, runs, "baseline", "spoofing", _run_baseline_spoofing),
            _run_scenario(run, runs, "secure", "spoofing", _run_secure_spoofing),
            _run_scenario(run, runs, "baseline", "replay", _run_baseline_replay),
            _run_scenario(run, runs, "secure", "replay", _run_secure_replay),
            _run_scenario(run, runs, "baseline", "dos", _run_baseline_dos, dos_count),
            _run_scenario(run, runs, "secure", "dos", _run_secure_dos, dos_count),
            _run_scenario(run, runs, "baseline", "benign", _run_baseline_benign),
            _run_scenario(run, runs, "secure", "benign", _run_secure_benign),
        ))

    return {
        "schema_version": 1,
        "environment": "python-can virtual bus; results are not hardware measurements",
        "configuration": {
            "runs": runs,
            "dos_count_per_run": dos_count,
            "benign_messages_per_run": BENIGN_MESSAGES,
        },
        "summary": summarize_comparison(records),
        "records": records,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compara ataques equivalentes en bus virtual: baseline y CAN-Secure."
    )
    parser.add_argument("--runs", type=int, default=3, help="corridas independientes por escenario (default: 3)")
    parser.add_argument("--dos-count", type=int, default=100, help="frames de la ráfaga DoS (mínimo: 51)")
    parser.add_argument("--output", help="ruta opcional para guardar el reporte JSON completo")
    args = parser.parse_args()

    try:
        report = run_comparison(args.runs, args.dos_count)
    except ValueError as error:
        parser.error(str(error))
    print_comparison_summary(report["summary"])
    if args.output:
        write_report(report, args.output)
        print(f"\nReporte JSON guardado en: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
