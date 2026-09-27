import can
from core.crypto import CryptoManager
from core.frame_codec import FrameCodec

def run_replay_attack(channel='virtual_bus', interface='virtual', target_id=0x100, old_seq=1):
    bus = can.interface.Bus(channel=channel, bustype=interface, fd=True)
    crypto = CryptoManager(b'secret_key_ecu1')
    
    data = b"OLD_COMMAND_DATA"
    payload_to_sign = data + old_seq.to_bytes(4, byteorder='big')
    mac = crypto.generate_mac(payload_to_sign)
    
    # Reenvía una trama anterior con un contador de secuencia ya usado (old_seq)
    msg1 = can.Message(arbitration_id=target_id, data=data, is_fd=True)
    auth_bytes = FrameCodec.pack_auth_frame(mac, old_seq)
    msg2 = can.Message(arbitration_id=target_id + 1, data=auth_bytes, is_fd=True)
    
    bus.send(msg1)
    bus.send(msg2)
    print(f"[Ataque Replay] Trama antigua reenviada con Seq: {old_seq}")

if __name__ == "__main__":
    run_replay_attack()