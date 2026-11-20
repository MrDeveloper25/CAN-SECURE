#   Importacion de librerias publicas
import time
import can
from cryptography.exceptions import InvalidTag

#   Importacion de librerias y variables del proyecto
from core.crypto import DEMO_KEY
from core.failure_policy import FailurePolicy
from core.frame_codec import (AUTH_FRAME_TYPE, DATA_FRAME_TYPE, FrameCodec, MAX_PLAINTEXT_SIZE,)
from core.frame_reassembler import FrameAssemblyError, FrameReassembler
from core.key_manager import KeyManager
from core.replay_guard import ReplayGuard


class SecureECU:
    #   Inicializar el objeto con parametros base, todo se mantiene igual a menos que sea especificado cuando se crea una instancia.
    def __init__(self, channel="virtual_bus", interface="virtual", secret_key=DEMO_KEY, key_manager=None, base_ids=None, reassembly_timeout=1.0, replay_state_path=None,):
        configured_ids = None if base_ids is None else FrameCodec.validate_base_ids(base_ids)
        self.base_ids = None if configured_ids is None else frozenset(configured_ids)
        self.reassembler = FrameReassembler(self.base_ids, timeout=reassembly_timeout)
        self.key_manager = key_manager if key_manager is not None else KeyManager(secret_key)
        self.replay_guard = ReplayGuard(replay_state_path)
        self.failure_policy = FailurePolicy()
        self.seq_counter = 0
        self.bus = can.interface.Bus(channel=channel, interface=interface, fd=True)

    #   Funcion para enviar trama
    def send_secure_frame(self, base_id: int, data: bytes):
        #   Validar ID Base
        FrameCodec.validate_base_id(base_id)
        if self.base_ids is not None and base_id not in self.base_ids:
            raise ValueError(f"El ID base {hex(base_id)} no esta reservado para esta ECU.")
        #   Validar el payload
        if not isinstance(data, bytes):
            raise TypeError("El payload debe ser de tipo bytes.")
        if len(data) > MAX_PLAINTEXT_SIZE:
            raise ValueError(f"El payload no puede superar {MAX_PLAINTEXT_SIZE} bytes.")
        self.seq_counter = self.key_manager.next_sequence(base_id)
        associated_data = FrameCodec.associated_data(base_id, self.seq_counter)
        nonce, ciphertext, tag = self.key_manager.encrypt(base_id, data, associated_data)

        self.bus.send(can.Message(
            arbitration_id=base_id,
            data=FrameCodec.pack_data_frame(ciphertext, self.seq_counter),
            is_fd=True,
            is_extended_id=False,
        ))
        self.bus.send(can.Message(
            arbitration_id=base_id + 1,
            data=FrameCodec.pack_auth_frame(
                nonce,
                tag,
                self.seq_counter,
                len(ciphertext),
            ),
            is_fd=True,
            is_extended_id=False,
        ))
        print(f"[ECU Sent] ID: {hex(base_id)} | Seq: {self.seq_counter}")

    def receive_and_verify(self, timeout=1.0):
        if timeout < 0:
            raise ValueError("El timeout de recepcion no puede ser negativo.")
        deadline = time.monotonic() + timeout

        while True:
            for base_id in self.reassembler.expire():
                self.failure_policy.register_failure(base_id)

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None

            message = self.bus.recv(timeout=remaining)
            if message is None:
                for base_id in self.reassembler.expire():
                    self.failure_policy.register_failure(base_id)
                return None

            if self.reassembler.reserved_ids is not None and message.arbitration_id not in self.reassembler.reserved_ids:
                continue

            for base_id in self.reassembler.expire():
                self.failure_policy.register_failure(base_id)
            try:
                assembled = self.reassembler.feed(
                    message.arbitration_id,
                    message.data,
                    is_fd=message.is_fd,
                    is_extended_id=message.is_extended_id,
                    is_remote_frame=message.is_remote_frame,
                    is_error_frame=message.is_error_frame,
                )
            except FrameAssemblyError as error:
                failed_id = error.base_id if error.base_id is not None else message.arbitration_id
                self.failure_policy.register_failure(failed_id)
                continue

            if assembled is None:
                if (
                    (not message.data or message.data[0] not in (DATA_FRAME_TYPE, AUTH_FRAME_TYPE))
                    and (
                        self.reassembler.reserved_ids is None
                        or message.arbitration_id in self.reassembler.reserved_ids
                    )
                ):
                    failed_id = message.arbitration_id
                    if message.data[:1] == bytes((AUTH_FRAME_TYPE,)):
                        failed_id -= 1
                    self.failure_policy.register_failure(failed_id)
                continue

            if not self.replay_guard.is_valid_sequence(assembled.base_id, assembled.seq_counter):
                self.failure_policy.register_failure(assembled.base_id)
                continue

            associated_data = FrameCodec.associated_data(assembled.base_id, assembled.seq_counter)
            try:
                plaintext = self.key_manager.decrypt(
                    assembled.base_id,
                    assembled.ciphertext,
                    assembled.nonce,
                    assembled.tag,
                    associated_data,
                )
            except InvalidTag:
                self.failure_policy.register_failure(assembled.base_id)
                continue

            if not self.replay_guard.accept_sequence(assembled.base_id, assembled.seq_counter):
                self.failure_policy.register_failure(assembled.base_id)
                continue
            self.failure_policy.reset_failures(assembled.base_id)
            return plaintext
