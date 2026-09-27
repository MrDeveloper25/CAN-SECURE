import threading
import time
from nodes.ids_monitor import IDSMonitor
from nodes.secure_ecu import SecureECU
from attacks.spoofing import run_spoofing_attack
from attacks.replay import run_replay_attack

def run_secure_eval():
    print("--- INICIANDO ESCENARIO CAN-SECURE ---")
    ids = IDSMonitor()
    ecu = SecureECU()
    
    # Enviar trafico legitimo
    ecu.send_secure_frame(0x100, b"ENGINE_RPM_3000")
    
    # Ejecutar ataques
    time.sleep(0.1)
    run_spoofing_attack(target_id=0x100)
    run_replay_attack(target_id=0x100, old_seq=1)
    
    # Monitorear con el IDS
    results = ids.start_monitoring(duration=2.0)
    return results

if __name__ == "__main__":
    res = run_secure_eval()
    print("[Secure Run Results]:", res)