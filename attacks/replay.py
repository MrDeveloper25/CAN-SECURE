import can
from core.crypto import CryptoManager, DEMO_KEY
from core.frame_codec import FrameCodec

def run_replay_attack(channel='virtual_bus', interface='virtual', target_id=0x100, old_seq=1):
    bus = can.interface.Bus(channel=channel, bustype=interface, fd=True)
    crypto = CryptoManager(DEMO_KEY)
    
    data = b"OLD_COMMAND_DATA"
    associated_data = FrameCodec.associated_data(target_id, old_seq)
    nonce, ciphertext, tag = crypto.encrypt(data, associated_data)
    
    # Genera un paquete valido de laboratorio con un contador ya utilizado.
    # En una red real, un replay debe reenviar exactamente los frames capturados.
    msg1 = can.Message(arbitration_id=target_id, data=ciphertext, is_fd=True)
    auth_bytes = FrameCodec.pack_auth_frame(nonce, tag, old_seq)
    msg2 = can.Message(arbitration_id=target_id + 1, data=auth_bytes, is_fd=True)
    
    bus.send(msg1)
    bus.send(msg2)
    print(f"[Ataque Replay] Trama antigua reenviada con Seq: {old_seq}")

if __name__ == "__main__":
    run_replay_attack()