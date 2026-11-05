import argparse
import can
import io
import uuid
from contextlib import redirect_stdout

from core.crypto import CryptoManager, DEMO_KEY
from core.frame_codec import FrameCodec
from nodes.ids_monitor import IDSMonitor
from nodes.secure_ecu import SecureECU


def _channel(test_name: str) -> str:
    return f"can_secure_manual_{test_name}_{uuid.uuid4().hex}"


def _report(name: str, expected: str, observed: str, passed: bool) -> bool:
    print(f"\nResultado: {'PASS' if passed else 'FAIL'} - {name}")
    print(f"  Esperado: {expected}")
    print(f"  Obtenido: {observed}")
    return passed


def test_valid_message() -> bool:
    name = "Mensaje legítimo"
    print(f"\n=== {name} ===")
    print("Proceso: la ECU cifra el payload con AES-GCM, envía dos frames y la ECU receptora verifica y descifra.")
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
    print(f"\n=== {name} ===")
    print("Proceso: se inyecta únicamente el frame de datos, sin el frame de autenticación AES-GCM.")
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
    print(f"\n=== {name} ===")
    print("Proceso: se cifra un mensaje válido, se modifica un bit del tag y se envían ambos frames.")
    channel = _channel("tampered")
    receiver = SecureECU(channel=channel)
    injector = can.interface.Bus(channel=channel, interface="virtual", fd=True)
    base_id = 0x120
    sequence = 9
    try:
        aad = FrameCodec.associated_data(base_id, sequence)
        nonce, ciphertext, tag = CryptoManager(DEMO_KEY).encrypt(b"ALTER_ME", aad)
        tampered_tag = tag[:-1] + bytes([tag[-1] ^ 1])
        injector.send(can.Message(arbitration_id=base_id, data=ciphertext, is_fd=True))
        injector.send(can.Message(
            arbitration_id=base_id + 1,
            data=FrameCodec.pack_auth_frame(nonce, tampered_tag, sequence),
            is_fd=True,
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
    print(f"\n=== {name} ===")
    print("Proceso: se capturan los dos frames de un mensaje válido, se acepta una vez y se reenvían sin modificarlos.")
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
    print(f"\n=== {name} ===")
    print("Proceso: el IDS inspecciona un par legítimo y después una trama sin su frame de autenticación.")
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
        for line in captured_output.getvalue().splitlines():
            print(f"  IDS: {line}")
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
    print(f"\n=== {name} ===")
    print("Proceso: se inyectan 160 frames en el bus virtual; el IDS aplica su umbral actual de 50 frames por segundo.")
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


TESTS = {
    "1": test_valid_message,
    "2": test_unauthenticated_frame,
    "3": test_tampered_tag,
    "4": test_replay,
    "5": test_ids_monitor,
    "6": test_dos_flood,
}


def _print_menu() -> None:
    print("\nCAN-Secure | pruebas manuales de desarrollo")
    print("  1. Mensaje legítimo: cifrado y descifrado")
    print("  2. Trama sin autenticación")
    print("  3. Tag AES-GCM alterado")
    print("  4. Reenvío exacto (replay)")
    print("  5. Monitor IDS: legítimo + spoofing")
    print("  6. Ráfaga DoS y umbral IDS")
    print("  0. Salir")


def main() -> int:
    parser = argparse.ArgumentParser(description="Pruebas guiadas de CAN-Secure sobre python-can virtual.")
    parser.add_argument("--all", action="store_true", help="ejecuta todos los escenarios y devuelve código de resultado")
    args = parser.parse_args()
    print("Modo de desarrollo: solo se usa el bus virtual de python-can; no se conecta a vcan0 ni a hardware CAN.")
    print("La clave incluida es de demostración y no debe usarse en producción.")

    if args.all:
        results = [test() for test in TESTS.values()]
        passed = sum(results)
        print(f"\nResumen: {passed}/{len(results)} pruebas PASS.")
        return 0 if passed == len(results) else 1

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
            test()
    except (EOFError, KeyboardInterrupt):
        print("\nFin de las pruebas manuales.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())