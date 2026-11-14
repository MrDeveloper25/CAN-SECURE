import can
from core.crypto import DEMO_KEY
from core.frame_codec import FrameCodec
from core.key_manager import KeyManager

def run_replay_attack(channel='virtual_bus', interface='virtual', target_id=0x100, old_seq=1):
    bus = can.interface.Bus(channel=channel, bustype=interface, fd=True)

    try:
        key_manager = KeyManager(DEMO_KEY)
        
        data = b"OLD_COMMAND_DATA"
        associated_data = FrameCodec.associated_data(target_id, old_seq)
        nonce, ciphertext, tag = key_manager.encrypt(target_id, data, associated_data)
        
        # Genera un paquete valido de laboratorio con un contador ya utilizado.
        # En una red real, un replay debe reenviar exactamente los frames capturados.
        msg1 = can.Message(
            arbitration_id=target_id,
            data=FrameCodec.pack_data_frame(ciphertext, old_seq),
            is_fd=True,
            is_extended_id=False,
        )
        auth_bytes = FrameCodec.pack_auth_frame(nonce, tag, old_seq, len(ciphertext))
        msg2 = can.Message(
            arbitration_id=target_id + 1,
            data=auth_bytes,
            is_fd=True,
            is_extended_id=False,
        )
        
        bus.send(msg1)
        bus.send(msg2)
        print(f"[Ataque Replay] Trama antigua reenviada con Seq: {old_seq}")

    finally:
        bus.shutdown()

if __name__ == "__main__":
    run_replay_attack()