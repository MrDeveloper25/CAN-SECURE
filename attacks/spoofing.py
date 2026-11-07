import can

from core import config


def run_spoofing_attack(channel=config.BUS_CHANNEL, interface=config.BUS_INTERFACE,
                        target_id=config.DATA_ID):
    """Inyecta una trama de datos SIN su frame de autenticacion (Frame 2).

    Al no existir MAC valido, CAN-Secure la rechaza y el IDS la reporta como
    trama no autenticada.
    """
    bus = can.Bus(channel=channel, interface=interface, fd=config.BUS_FD,
                  receive_own_messages=False)
    fake_data = b"FAKE_SPEED_200KMH"
    bus.send(can.Message(arbitration_id=target_id, data=fake_data, is_fd=config.BUS_FD))
    print(f"[Ataque Spoofing] Trama falsificada enviada a ID: {hex(target_id)}")
    bus.shutdown()


if __name__ == "__main__":
    run_spoofing_attack()
