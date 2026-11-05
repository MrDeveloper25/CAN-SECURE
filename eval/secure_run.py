
import time
import can

from nodes.ids_monitor import IDSMonitor
from nodes.secure_ecu import SecureECU
from core.key_manager import KeyManager
from core.crypto import CryptoManager, DEMO_KEY
from core.frame_codec import FrameCodec
from attacks.spoofing import run_spoofing_attack
from attacks.replay import run_replay_attack


def run_secure_eval():
    print("--- INICIANDO ESCENARIO CAN-SECURE ---")

    key_manager = KeyManager()
    ids = IDSMonitor(key_manager=key_manager)
    ecu = SecureECU(key_manager=key_manager)

    try:
        ecu.send_secure_frame(0x100, b"ENGINE_RPM_3000")
        time.sleep(0.1)

        run_replay_attack(target_id=0x100, old_seq=1)
        time.sleep(0.1)

        run_spoofing_attack(target_id=0x100)

        results = ids.start_monitoring(duration=2.0)

        print("\n--- PREPARANDO TRAMA CON CLAVE ANTERIOR ---")

        old_crypto = CryptoManager(DEMO_KEY)

        old_seq = 3
        old_data = b"OLD_KEY_COMMAND"
        old_aad = FrameCodec.associated_data(0x100, old_seq)

        old_nonce, old_ciphertext, old_tag = old_crypto.encrypt(
            old_data,
            old_aad
        )

        old_auth = FrameCodec.pack_auth_frame(
            old_nonce,
            old_tag,
            old_seq
        )

        print("\n--- ROTACION DE CLAVE AES-GCM ---")

        new_key = b"A" * 32
        key_manager.rotate_key(new_key)

        ecu.send_secure_frame(0x100, b"ENGINE_RPM_3500")
        time.sleep(0.1)

        print("\n--- VERIFICANDO NUEVA CLAVE ---")

        rotation_results = ids.start_monitoring(duration=1.0)

        print("\n--- RESULTADOS DE ROTACION ---")
        print(rotation_results)

        print("\n--- PROBANDO RECHAZO DE CLAVE ANTERIOR ---")

        old_bus = can.interface.Bus(
            channel='virtual_bus',
            interface='virtual',
            fd=True
        )

        try:
            old_msg1 = can.Message(
                arbitration_id=0x100,
                data=old_ciphertext,
                is_fd=True
            )

            old_msg2 = can.Message(
                arbitration_id=0x101,
                data=old_auth,
                is_fd=True
            )

            old_bus.send(old_msg1)
            old_bus.send(old_msg2)

            print("[Test] Trama cifrada con clave anterior enviada.")

        finally:
            old_bus.shutdown()

        time.sleep(0.1)

        old_key_results = ids.start_monitoring(duration=1.0)

        print("\n--- RESULTADOS DE RECHAZO DE CLAVE ANTERIOR ---")
        print(old_key_results)

        return results, rotation_results, old_key_results

    finally:
        ids.bus.shutdown()
        ecu.bus.shutdown()


if __name__ == "__main__":
    res = run_secure_eval()
    print("[Secure Run Results]:", res)
