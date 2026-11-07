import can

from core import config
from core.crypto import CryptoManager
from core.frame_codec import FrameCodec


def run_replay_attack(target_id=config.DATA_ID, old_seq=1,
                      secret_key=config.DEFAULT_SECRET_KEY):
    """Reenvia una trama anterior (datos + MAC validos) con un contador ya usado.

    El MAC es criptograficamente valido: lo que delata el ataque es el contador
    de secuencia repetido, que el ReplayGuard del receptor rechaza.
    """
    bus = config.make_bus(receive_own_messages=False)
    crypto = CryptoManager(secret_key)

    data = b"OLD_COMMAND_DATA"[: 8 if not config.BUS_FD else 64]
    payload_to_sign = data + old_seq.to_bytes(config.SEQ_COUNTER_BYTES, "big")
    mac = crypto.generate_mac(payload_to_sign)

    bus.send(can.Message(arbitration_id=target_id, data=data, is_fd=config.BUS_FD))
    auth_bytes = FrameCodec.pack_auth_frame(mac, old_seq)
    bus.send(can.Message(arbitration_id=config.auth_id_for(target_id),
                         data=auth_bytes, is_fd=config.BUS_FD))
    print(f"[Ataque Replay] Trama antigua reenviada con Seq: {old_seq}")
    bus.shutdown()


if __name__ == "__main__":
    run_replay_attack()
