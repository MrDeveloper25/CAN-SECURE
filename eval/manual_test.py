import argparse
import can
from concurrent.futures import ThreadPoolExecutor
import io
import os
import stat
import tempfile
import time
import uuid
from contextlib import redirect_stdout

from cryptography.exceptions import InvalidTag

from core.crypto import DEMO_KEY
from core.frame_codec import (
    CAN_FD_DLC_LENGTHS,
    MAX_PLAINTEXT_SIZE,
    FrameCodec,
)
from core.key_manager import KeyManager
from core.replay_guard import ReplayGuard
from nodes.ids_monitor import IDSMonitor
from nodes.secure_ecu import SecureECU

_ACTIVE_TEST_STARTED: float | None = None
_ACTIVE_TEST_GROUP = ""
_TEST_RESULTS: list[dict] = []


def _channel(test_name: str) -> str:
    return f"can_secure_manual_{test_name}_{uuid.uuid4().hex}"


def _report(name: str, expected: str, observed: str, passed: bool) -> bool:
    elapsed_ms = (
        (time.perf_counter() - _ACTIVE_TEST_STARTED) * 1000
        if _ACTIVE_TEST_STARTED is not None
        else 0.0
    )
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] {name} | {observed} | {elapsed_ms:.1f} ms", flush=True)
    if not passed:
        print(f"       Esperado: {expected}", flush=True)
    _TEST_RESULTS.append({
        "name": name,
        "group": _ACTIVE_TEST_GROUP,
        "passed": passed,
        "elapsed_ms": elapsed_ms,
    })
    return passed


def _protected_frames(base_id: int, sequence: int, payload: bytes):
    associated_data = FrameCodec.associated_data(base_id, sequence)
    nonce, ciphertext, tag = KeyManager(DEMO_KEY).encrypt(base_id, payload, associated_data)
    return (
        can.Message(
            arbitration_id=base_id,
            data=FrameCodec.pack_data_frame(ciphertext, sequence),
            is_fd=True,
            is_extended_id=False,
        ),
        can.Message(
            arbitration_id=base_id + 1,
            data=FrameCodec.pack_auth_frame(nonce, tag, sequence, len(ciphertext)),
            is_fd=True,
            is_extended_id=False,
        ),
    )


def test_valid_message() -> bool:
    name = "Mensaje legítimo"
    channel = _channel("valid")
    sender = SecureECU(channel=channel)
    receiver = SecureECU(channel=channel)
    payload = b"ENGINE_RPM_3000"
    try:
        sender.send_secure_frame(0x100, payload)
        received = receiver.receive_and_verify(timeout=0.5)
        passed = received == payload
        observed = f"payload recuperado: {received!r}" if received is not None else "mensaje rechazado o no recibido"
        return _report(name, f"payload recuperado exactamente: {payload!r}", observed, passed)
    finally:
        sender.bus.shutdown()
        receiver.bus.shutdown()


def test_unauthenticated_frame() -> bool:
    name = "Trama sin autenticación"
    channel = _channel("unauthenticated")
    receiver = SecureECU(channel=channel)
    injector = can.interface.Bus(channel=channel, interface="virtual", fd=True)
    base_id = 0x110
    try:
        injector.send(can.Message(arbitration_id=base_id, data=b"FAKE_COMMAND", is_fd=True))
        received = receiver.receive_and_verify(timeout=0.5)
        failures = receiver.failure_policy.failure_counts.get(base_id, 0)
        passed = received is None and failures == 1
        observed = f"payload={received!r}, fallos registrados para ID {hex(base_id)}={failures}"
        return _report(name, "payload rechazado y un fallo registrado", observed, passed)
    finally:
        injector.shutdown()
        receiver.bus.shutdown()


def test_tampered_tag() -> bool:
    name = "Tag AES-GCM alterado"
    channel = _channel("tampered")
    receiver = SecureECU(channel=channel)
    injector = can.interface.Bus(channel=channel, interface="virtual", fd=True)
    base_id = 0x120
    sequence = 9
    try:
        aad = FrameCodec.associated_data(base_id, sequence)
        nonce, ciphertext, tag = KeyManager(DEMO_KEY).encrypt(base_id, b"ALTER_ME", aad)
        tampered_tag = tag[:-1] + bytes([tag[-1] ^ 1])
        injector.send(can.Message(
            arbitration_id=base_id,
            data=FrameCodec.pack_data_frame(ciphertext, sequence),
            is_fd=True,
            is_extended_id=False,
        ))
        injector.send(can.Message(
            arbitration_id=base_id + 1,
            data=FrameCodec.pack_auth_frame(nonce, tampered_tag, sequence, len(ciphertext)),
            is_fd=True,
            is_extended_id=False,
        ))
        received = receiver.receive_and_verify(timeout=0.5)
        accepted_sequence = receiver.replay_guard.last_counters.get(base_id)
        passed = received is None and accepted_sequence is None
        observed = f"payload={received!r}, último contador aceptado={accepted_sequence!r}"
        return _report(name, "tag inválido rechazado y contador anti-replay sin cambios", observed, passed)
    finally:
        injector.shutdown()
        receiver.bus.shutdown()


def test_replay() -> bool:
    name = "Reenvío exacto (replay)"
    channel = _channel("replay")
    sender = SecureECU(channel=channel)
    receiver = SecureECU(channel=channel)
    sniffer = can.interface.Bus(channel=channel, interface="virtual", fd=True)
    attacker = can.interface.Bus(channel=channel, interface="virtual", fd=True)
    base_id = 0x130
    try:
        sender.send_secure_frame(base_id, b"BRAKE_STATUS")
        captured = [sniffer.recv(timeout=0.5), sniffer.recv(timeout=0.5)]
        if any(frame is None for frame in captured):
            return _report(name, "dos frames capturados", "no se capturó el par completo", False)

        first_delivery = receiver.receive_and_verify(timeout=0.5)
        for frame in captured:
            attacker.send(can.Message(
                arbitration_id=frame.arbitration_id,
                data=frame.data,
                is_fd=frame.is_fd,
                is_extended_id=frame.is_extended_id,
            ))
        replay_delivery = receiver.receive_and_verify(timeout=0.5)
        accepted_sequence = receiver.replay_guard.last_counters.get(base_id)
        passed = first_delivery == b"BRAKE_STATUS" and replay_delivery is None and accepted_sequence == 1
        observed = (
            f"primera entrega={first_delivery!r}, replay={replay_delivery!r}, "
            f"último contador aceptado={accepted_sequence}"
        )
        return _report(name, "primera entrega aceptada y repetición rechazada", observed, passed)
    finally:
        sender.bus.shutdown()
        receiver.bus.shutdown()
        sniffer.shutdown()
        attacker.shutdown()


def test_ids_monitor() -> bool:
    name = "Monitor IDS"
    channel = _channel("ids")
    sender = SecureECU(channel=channel)
    ids = IDSMonitor(channel=channel)
    injector = can.interface.Bus(channel=channel, interface="virtual", fd=True)
    try:
        sender.send_secure_frame(0x140, b"VALID_SENSOR_DATA")
        injector.send(can.Message(arbitration_id=0x150, data=b"UNAUTHENTICATED", is_fd=True))
        captured_output = io.StringIO()
        with redirect_stdout(captured_output):
            metrics = ids.start_monitoring(duration=0.2)
        passed = metrics["valid_frames"] == 1 and metrics["spoofing_detected"] >= 1
        observed = (
            f"válidas={metrics['valid_frames']}, spoofing/tramas sin autenticación="
            f"{metrics['spoofing_detected']}"
        )
        return _report(name, "una trama válida y al menos una trama insegura detectada", observed, passed)
    finally:
        sender.bus.shutdown()
        ids.bus.shutdown()
        injector.shutdown()


def test_dos_flood() -> bool:
    name = "Alerta de frecuencia (DoS)"
    channel = _channel("dos")
    ids = IDSMonitor(channel=channel)
    injector = can.interface.Bus(channel=channel, interface="virtual", fd=True)
    try:
        for _ in range(160):
            injector.send(can.Message(arbitration_id=0x000, data=b"\xff" * 8, is_fd=True))
        with redirect_stdout(io.StringIO()):
            metrics = ids.start_monitoring(duration=2.0)
        passed = metrics["dos_alerts"] > 0
        observed = (
            f"frames procesados={metrics['total_frames']}, alertas de frecuencia="
            f"{metrics['dos_alerts']}"
        )
        return _report(name, "al menos una alerta de frecuencia DoS", observed, passed)
    finally:
        ids.bus.shutdown()
        injector.shutdown()


def test_interleaved_frames() -> bool:
    name = "Frames intercalados y fuera de orden"
    channel = _channel("interleaved")
    base_ids = (0x160, 0x162)
    receiver = SecureECU(channel=channel, base_ids=base_ids)
    ids = IDSMonitor(channel=channel, base_ids=base_ids)
    injector = can.interface.Bus(channel=channel, interface="virtual", fd=True)
    try:
        first = _protected_frames(0x160, 1, b"FIRST_MESSAGE")
        second = _protected_frames(0x162, 1, b"SECOND_MESSAGE")
        for frame in (first[0], second[1], second[0], first[1]):
            injector.send(frame)

        received = (
            receiver.receive_and_verify(timeout=0.5),
            receiver.receive_and_verify(timeout=0.5),
        )
        with redirect_stdout(io.StringIO()):
            metrics = ids.start_monitoring(duration=0.1)
        passed = (
            received == (b"SECOND_MESSAGE", b"FIRST_MESSAGE")
            and metrics["valid_frames"] == 2
        )
        observed = f"ECU={received!r}, IDS verifico {metrics['valid_frames']} mensajes"
        return _report(
            name,
            "ambos pares se asocian por ID/contador aunque lleguen intercalados y fuera de orden",
            observed,
            passed,
        )
    finally:
        receiver.bus.shutdown()
        ids.bus.shutdown()
        injector.shutdown()


def test_incomplete_pair_timeout() -> bool:
    name = "Perdida de frame y timeout"
    channel = _channel("incomplete")
    receiver = SecureECU(channel=channel, reassembly_timeout=0.02)
    injector = can.interface.Bus(channel=channel, interface="virtual", fd=True)
    base_id = 0x170
    try:
        data_frame, _ = _protected_frames(base_id, 1, b"INCOMPLETE")
        injector.send(data_frame)
        received = receiver.receive_and_verify(timeout=0.1)
        failures = receiver.failure_policy.failure_counts.get(base_id, 0)
        passed = received is None and failures == 1 and receiver.reassembler.pending_count == 0
        observed = (
            f"payload={received!r}, fallos={failures}, "
            f"pares pendientes={receiver.reassembler.pending_count}"
        )
        return _report(
            name,
            "un par incompleto expira, no entrega payload y registra el fallo",
            observed,
            passed,
        )
    finally:
        receiver.bus.shutdown()
        injector.shutdown()


def test_duplicate_partial_frame() -> bool:
    name = "Duplicado de un frame parcial"
    channel = _channel("duplicate")
    receiver = SecureECU(channel=channel)
    injector = can.interface.Bus(channel=channel, interface="virtual", fd=True)
    base_id = 0x172
    try:
        data_frame, auth_frame = _protected_frames(base_id, 1, b"ONE_DELIVERY")
        injector.send(data_frame)
        injector.send(data_frame)
        injector.send(auth_frame)
        first_delivery = receiver.receive_and_verify(timeout=0.1)
        duplicate_delivery = receiver.receive_and_verify(timeout=0.02)
        accepted_sequence = receiver.replay_guard.last_counters.get(base_id)
        passed = (
            first_delivery == b"ONE_DELIVERY"
            and duplicate_delivery is None
            and accepted_sequence == 1
        )
        observed = (
            f"primera entrega={first_delivery!r}, segunda entrega={duplicate_delivery!r}, "
            f"ultimo contador={accepted_sequence}"
        )
        return _report(
            name,
            "el duplicado no crea otra entrega y el par original se mantiene verificable",
            observed,
            passed,
        )
    finally:
        receiver.bus.shutdown()
        injector.shutdown()


def test_persistent_key_state() -> bool:
    name = "Persistencia de clave, nonce y anti-replay"
    with tempfile.TemporaryDirectory(prefix="can-secure-keys-") as directory:
        state_path = os.path.join(directory, "key-state.json")
        base_id = 0x190
        first_manager = KeyManager.persistent(state_path)
        first_key = first_manager.get_key()
        first_sequence = first_manager.next_sequence(base_id)
        first_aad = FrameCodec.associated_data(base_id, first_sequence)
        first_nonce, first_ciphertext, first_tag = first_manager.encrypt(
            base_id,
            b"PERSISTED_MESSAGE",
            first_aad,
        )

        receiver_manager = KeyManager.persistent(state_path)
        first_plaintext = receiver_manager.decrypt(
            base_id,
            first_ciphertext,
            first_nonce,
            first_tag,
            first_aad,
        )
        replay_path = os.path.join(directory, "ecu-replay.json")
        replay_guard = ReplayGuard(replay_path)
        first_accepted = replay_guard.accept_sequence(base_id, first_sequence)
        restarted_manager = KeyManager.persistent(state_path)
        next_sequence = restarted_manager.next_sequence(base_id)
        next_aad = FrameCodec.associated_data(base_id, next_sequence)
        next_nonce, _, _ = restarted_manager.encrypt(
            base_id,
            b"AFTER_RESTART",
            next_aad,
        )
        restarted_guard = ReplayGuard(replay_path)
        file_mode = stat.S_IMODE(os.stat(state_path).st_mode)
        os.chmod(state_path, 0o644)
        insecure_mode_rejected = False
        try:
            KeyManager.persistent(state_path)
        except PermissionError:
            insecure_mode_rejected = True
        finally:
            os.chmod(state_path, 0o600)
        passed = (
            first_key == receiver_manager.get_key() == restarted_manager.get_key()
            and first_plaintext == b"PERSISTED_MESSAGE"
            and first_accepted
            and next_sequence == first_sequence + 1
            and next_nonce != first_nonce
            and not restarted_guard.is_valid_sequence(base_id, first_sequence)
            and file_mode == 0o600
            and insecure_mode_rejected
        )
        observed = (
            f"misma clave={first_key == restarted_manager.get_key()}, "
            f"secuencia tras reinicio={next_sequence}, nonce distinto={next_nonce != first_nonce}, "
            f"replay tras reinicio rechazado={not restarted_guard.is_valid_sequence(base_id, first_sequence)}, "
            f"permisos={file_mode:o}, permisos inseguros rechazados={insecure_mode_rejected}"
        )
        return _report(
            name,
            "clave y estado sobreviven reinicio; secuencia/nonce avanzan y replay previo se rechaza",
            observed,
            passed,
        )


def test_persistent_key_rotation() -> bool:
    name = "Rotación y no reutilización de claves"
    with tempfile.TemporaryDirectory(prefix="can-secure-rotation-") as directory:
        state_path = os.path.join(directory, "key-state.json")
        base_id = 0x192
        manager = KeyManager.persistent(state_path)
        old_key = manager.get_key()
        old_sequence = manager.next_sequence(base_id)
        old_aad = FrameCodec.associated_data(base_id, old_sequence)
        old_nonce, old_ciphertext, old_tag = manager.encrypt(
            base_id,
            b"BEFORE_ROTATION",
            old_aad,
        )

        new_key = b"R" * 32
        manager.rotate_key(new_key)
        new_sequence = manager.next_sequence(base_id)
        restarted_manager = KeyManager.persistent(state_path)
        reuse_rejected = False
        try:
            restarted_manager.rotate_key(old_key)
        except ValueError:
            reuse_rejected = True

        invalidated_old_key = False
        try:
            manager.decrypt(base_id, old_ciphertext, old_nonce, old_tag, old_aad)
        except InvalidTag:
            invalidated_old_key = True

        passed = (
            manager.get_key() == restarted_manager.get_key() == new_key
            and new_sequence == old_sequence + 1
            and reuse_rejected
            and invalidated_old_key
        )
        observed = (
            f"clave nueva persistida={restarted_manager.get_key() == new_key}, "
            f"contador continuo={new_sequence == old_sequence + 1}, "
            f"clave anterior no reutilizable={reuse_rejected}, "
            f"mensaje anterior no valida con clave nueva={invalidated_old_key}"
        )
        return _report(
            name,
            "rotación persiste, contador se conserva y no se reutiliza una clave anterior",
            observed,
            passed,
        )


def test_sender_receiver_restart() -> bool:
    name = "Reinicio de emisor y receptor persistentes"
    with tempfile.TemporaryDirectory(prefix="can-secure-restart-") as directory:
        state_path = os.path.join(directory, "shared-key-state.json")
        replay_path = os.path.join(directory, "ecu-replay.json")
        channel = _channel("persistent-restart")
        base_id = 0x194
        sender = SecureECU(
            channel=channel,
            key_manager=KeyManager.persistent(state_path),
        )
        receiver = SecureECU(
            channel=channel,
            key_manager=KeyManager.persistent(state_path),
            replay_state_path=replay_path,
        )
        sniffer = can.interface.Bus(channel=channel, interface="virtual", fd=True)
        attacker = can.interface.Bus(channel=channel, interface="virtual", fd=True)
        try:
            sender.send_secure_frame(base_id, b"BEFORE_RESTART")
            captured = [sniffer.recv(timeout=0.5), sniffer.recv(timeout=0.5)]
            first_delivery = receiver.receive_and_verify(timeout=0.5)
        finally:
            sender.bus.shutdown()
            receiver.bus.shutdown()
            sniffer.shutdown()

        restarted_sender = SecureECU(
            channel=channel,
            key_manager=KeyManager.persistent(state_path),
        )
        restarted_receiver = SecureECU(
            channel=channel,
            key_manager=KeyManager.persistent(state_path),
            replay_state_path=replay_path,
        )
        try:
            restarted_sender.send_secure_frame(base_id, b"AFTER_RESTART")
            second_delivery = restarted_receiver.receive_and_verify(timeout=0.5)
            for frame in captured:
                attacker.send(can.Message(
                    arbitration_id=frame.arbitration_id,
                    data=frame.data,
                    is_fd=frame.is_fd,
                    is_extended_id=frame.is_extended_id,
                ))
            replay_delivery = restarted_receiver.receive_and_verify(timeout=0.1)
            passed = (
                first_delivery == b"BEFORE_RESTART"
                and second_delivery == b"AFTER_RESTART"
                and replay_delivery is None
                and restarted_sender.seq_counter == 2
            )
            observed = (
                f"antes={first_delivery!r}, despues={second_delivery!r}, "
                f"replay tras reinicio={replay_delivery!r}, "
                f"contador emisor={restarted_sender.seq_counter}"
            )
            return _report(
                name,
                "el emisor continua contador y el receptor conserva replay guard tras reinicios",
                observed,
                passed,
            )
        finally:
            restarted_sender.bus.shutdown()
            restarted_receiver.bus.shutdown()
            attacker.shutdown()


def test_concurrent_nonce_reservations() -> bool:
    name = "Reservas concurrentes de nonce"
    with tempfile.TemporaryDirectory(prefix="can-secure-concurrent-") as directory:
        state_path = os.path.join(directory, "key-state.json")
        base_id = 0x196
        managers = [KeyManager.persistent(state_path) for _ in range(4)]

        def reserve(index: int):
            manager = managers[index % len(managers)]
            sequence = manager.next_sequence(base_id)
            associated_data = FrameCodec.associated_data(base_id, sequence)
            nonce, _, _ = manager.encrypt(base_id, b"CONCURRENT", associated_data)
            return sequence, nonce

        with ThreadPoolExecutor(max_workers=len(managers)) as executor:
            reservations = list(executor.map(reserve, range(40)))
        sequences = [sequence for sequence, _ in reservations]
        nonces = [nonce for _, nonce in reservations]
        passed = len(set(sequences)) == 40 and len(set(nonces)) == 40
        observed = (
            f"contadores unicos={len(set(sequences))}/40, "
            f"nonces unicos={len(set(nonces))}/40"
        )
        return _report(
            name,
            "varios gestores sobre el mismo almacen reservan valores unicos",
            observed,
            passed,
        )


def test_protocol_limits_and_id_reservation() -> bool:
    name = "Limites de payload y reserva de IDs"
    channel = _channel("limits")
    sender = SecureECU(channel=channel, base_ids=(0x180,))
    receiver = SecureECU(channel=channel, base_ids=(0x180,))
    too_large_rejected = False
    overlap_rejected = False
    try:
        try:
            sender.send_secure_frame(0x180, b"X" * (MAX_PLAINTEXT_SIZE + 1))
        except ValueError:
            too_large_rejected = True
        try:
            FrameCodec.validate_base_ids((0x180, 0x181))
        except ValueError:
            overlap_rejected = True

        payload = b"Y" * MAX_PLAINTEXT_SIZE
        data_frame, auth_frame = _protected_frames(0x180, 1, payload)
        sender.send_secure_frame(0x180, payload)
        received = receiver.receive_and_verify(timeout=0.5)
        dlc_valid = len(data_frame.data) in CAN_FD_DLC_LENGTHS and len(auth_frame.data) in CAN_FD_DLC_LENGTHS
        passed = too_large_rejected and overlap_rejected and received == payload and dlc_valid
        observed = (
            f"payload excesivo rechazado={too_large_rejected}, "
            f"IDs solapados rechazados={overlap_rejected}, "
            f"payload maximo recuperado={received == payload}, DLC validos={dlc_valid}"
        )
        return _report(
            name,
            f"se rechaza >{MAX_PLAINTEXT_SIZE} bytes y pares de IDs solapados, "
            "y se acepta el payload maximo",
            observed,
            passed,
        )
    finally:
        sender.bus.shutdown()
        receiver.bus.shutdown()


TESTS = {
    "1": test_valid_message,
    "2": test_unauthenticated_frame,
    "3": test_tampered_tag,
    "4": test_replay,
    "5": test_ids_monitor,
    "6": test_dos_flood,
    "7": test_interleaved_frames,
    "8": test_incomplete_pair_timeout,
    "9": test_protocol_limits_and_id_reservation,
    "10": test_duplicate_partial_frame,
    "11": test_persistent_key_state,
    "12": test_persistent_key_rotation,
    "13": test_sender_receiver_restart,
    "14": test_concurrent_nonce_reservations,
}

TEST_LABELS = {
    "1": "Mensaje legítimo",
    "2": "Trama sin autenticación",
    "3": "Tag AES-GCM alterado",
    "4": "Reenvío exacto (replay)",
    "5": "Monitor IDS",
    "6": "Alerta de frecuencia DoS",
    "7": "Frames intercalados/fuera de orden",
    "8": "Pérdida de frame y timeout",
    "9": "Límites de payload y reserva de IDs",
    "10": "Duplicado de un frame parcial",
    "11": "Persistencia de clave, nonce y anti-replay",
    "12": "Rotación y no reutilización de claves",
    "13": "Reinicio de emisor y receptor persistentes",
    "14": "Reservas concurrentes de nonce",
}


def _print_menu() -> None:
    print("\nCAN-Secure | pruebas manuales de desarrollo")
    for key, label in TEST_LABELS.items():
        print(f"  {key}. {label}")
    print("  0. Salir")


def _run_test(key: str, test, index: int, total: int) -> bool:
    global _ACTIVE_TEST_STARTED, _ACTIVE_TEST_GROUP
    label = TEST_LABELS[key]
    _ACTIVE_TEST_STARTED = time.perf_counter()
    _ACTIVE_TEST_GROUP = "protocolo/IDS" if int(key) <= 10 else "claves/estado"
    print(f"[RUN ] {index}/{total} {label}", flush=True)
    try:
        return test()
    finally:
        _ACTIVE_TEST_STARTED = None


def _print_summary(started_at: float) -> None:
    elapsed = time.perf_counter() - started_at
    passed = sum(result["passed"] for result in _TEST_RESULTS)
    failed = [result["name"] for result in _TEST_RESULTS if not result["passed"]]
    print(
        f"\nResumen: {passed}/{len(_TEST_RESULTS)} PASS, "
        f"{len(failed)} FAIL | tiempo total {elapsed:.2f} s",
        flush=True,
    )
    for group in ("protocolo/IDS", "claves/estado"):
        results = [result for result in _TEST_RESULTS if result["group"] == group]
        if results:
            group_passed = sum(result["passed"] for result in results)
            print(f"  {group}: {group_passed}/{len(results)} PASS", flush=True)
    if failed:
        print(f"  Fallidas: {', '.join(failed)}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Pruebas guiadas de CAN-Secure sobre python-can virtual.")
    parser.add_argument("--all", action="store_true", help="ejecuta todos los escenarios y devuelve código de resultado")
    args = parser.parse_args()
    _TEST_RESULTS.clear()
    suite_started_at = time.perf_counter()
    print("Modo de desarrollo: solo se usa el bus virtual de python-can; no se conecta a vcan0 ni a hardware CAN.")
    print("La clave incluida es de demostración y no debe usarse en producción.")

    if args.all:
        results = [
            _run_test(key, test, index, len(TESTS))
            for index, (key, test) in enumerate(TESTS.items(), start=1)
        ]
        _print_summary(suite_started_at)
        return 0 if all(results) else 1

    try:
        while True:
            _print_menu()
            choice = input("Selecciona una prueba: ").strip()
            if choice == "0":
                print("Fin de las pruebas manuales.")
                return 0
            test = TESTS.get(choice)
            if test is None:
                print("Opción no válida; selecciona un número del menú.")
                continue
            _run_test(choice, test, 1, 1)
            _print_summary(suite_started_at)
    except (EOFError, KeyboardInterrupt):
        print("\nFin de las pruebas manuales.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())