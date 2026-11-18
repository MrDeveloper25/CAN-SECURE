import can
from attacks.spoofing import run_spoofing_attack
from attacks.dos_flood import run_dos_attack

def run_baseline():
    print('INICIANDO ESCENARIO BASELINE')
    bus = can.interface.Bus(channel='virtual_bus', bustype='virtual', fd=True)
    
    # En un bus sin CAN-Secure, todo mensaje inyectado es aceptado sin validación
    run_spoofing_attack()
    msg_spoofing = bus.recv(timeout=1.0)
    
    if msg_spoofing:
        print(f"[Spoofing] Trama ejecutada: {msg_spoofing.data}")
        
    run_dos_attack(count=10000)
    msg_dos = bus.recv(timeout=1.0)
    if(msg_dos):
        print(f'[DOS] Trama ejecutada: {msg_dos.data}')

if __name__ == "__main__":
    run_baseline()