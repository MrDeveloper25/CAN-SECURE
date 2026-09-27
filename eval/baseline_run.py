import can
import time
from attacks.spoofing import run_spoofing_attack

def run_baseline():
    print("--- INICIANDO ESCENARIO BASELINE (SIN PROTECCIÓN) ---")
    bus = can.interface.Bus(channel='virtual_bus', bustype='virtual', fd=True)
    
    # En un bus sin CAN-Secure, todo mensaje inyectado es aceptado sin validación
    run_spoofing_attack()
    msg = bus.recv(timeout=1.0)
    
    if msg:
        print(f"[Baseline Result] Trama aceptada directamente sin verificar: {msg.data}")
        print("Deteccion de ataques: 0%")

if __name__ == "__main__":
    run_baseline()