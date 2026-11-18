import struct

from core.crypto import AES_GCM_NONCE_SIZE, AES_GCM_TAG_SIZE

CAN_FD_MAX_DATA_SIZE = 64
CAN_FD_DLC_LENGTHS = tuple(range(9)) + (12, 16, 20, 24, 32, 48, 64)
DATA_FRAME_TYPE = 0xC1
AUTH_FRAME_TYPE = 0xC2
FRAME_HEADER_SIZE = 5
MAX_CIPHERTEXT_SIZE = CAN_FD_MAX_DATA_SIZE - FRAME_HEADER_SIZE
MAX_PLAINTEXT_SIZE = MAX_CIPHERTEXT_SIZE
AUTH_CIPHERTEXT_LENGTH_SIZE = 1
AUTH_NONCE_OFFSET = FRAME_HEADER_SIZE + AUTH_CIPHERTEXT_LENGTH_SIZE
AUTH_TAG_OFFSET = AUTH_NONCE_OFFSET + AES_GCM_NONCE_SIZE
AUTH_LOGICAL_SIZE = AUTH_TAG_OFFSET + AES_GCM_TAG_SIZE
AUTH_FRAME_SIZE = 48


class FrameCodec:
    @staticmethod
    def _padded_frame_size(logical_size: int) -> int:
        for size in CAN_FD_DLC_LENGTHS:
            if logical_size <= size:
                return size
        raise ValueError("El frame excede el payload maximo de CAN-FD.")

    @staticmethod
    def validate_base_id(base_id: int) -> None:
        if isinstance(base_id, bool) or not isinstance(base_id, int):
            raise TypeError("El ID base debe ser un entero.")
        if not 0 <= base_id <= 0x7FE:
            raise ValueError("El ID base debe permitir un par dentro del rango CAN estándar de 11 bits.")

    @staticmethod
    def validate_base_ids(base_ids) -> tuple[int, ...]:
        ids = tuple(base_ids)
        if len(set(ids)) != len(ids):
            raise ValueError("La lista de IDs base contiene duplicados.")
        for base_id in ids:
            FrameCodec.validate_base_id(base_id)
        sorted_ids = sorted(ids)
        if any(right == left + 1 for left, right in zip(sorted_ids, sorted_ids[1:])):
            raise ValueError("Los pares de IDs CAN reservados no pueden solaparse.")
        return ids

    @staticmethod
    def _validate_sequence(seq_counter: int) -> None:
        if isinstance(seq_counter, bool) or not isinstance(seq_counter, int):
            raise TypeError("El contador de secuencia debe ser un entero.")
        if not 1 <= seq_counter <= 0xFFFFFFFF:
            raise ValueError("El contador de secuencia debe estar entre 1 y 2^32-1.")

    @staticmethod
    def pack_data_frame(ciphertext: bytes, seq_counter: int) -> bytes:
        if not isinstance(ciphertext, bytes):
            raise TypeError("El ciphertext debe ser de tipo bytes.")
        if len(ciphertext) > MAX_CIPHERTEXT_SIZE:
            raise ValueError(f"El payload cifrado no puede superar {MAX_CIPHERTEXT_SIZE} bytes.")
        FrameCodec._validate_sequence(seq_counter)
        payload = bytes((DATA_FRAME_TYPE,)) + struct.pack(">I", seq_counter) + ciphertext
        return payload.ljust(FrameCodec._padded_frame_size(len(payload)), b"\x00")

    @staticmethod
    def unpack_data_frame(data_payload: bytes) -> tuple[int, bytes]:
        if (
            len(data_payload) < FRAME_HEADER_SIZE
            or len(data_payload) not in CAN_FD_DLC_LENGTHS
            or data_payload[0] != DATA_FRAME_TYPE
        ):
            raise ValueError("Frame de datos CAN-Secure malformado.")
        seq_counter = struct.unpack(">I", data_payload[1:FRAME_HEADER_SIZE])[0]
        FrameCodec._validate_sequence(seq_counter)
        return seq_counter, data_payload[FRAME_HEADER_SIZE:]

    @staticmethod
    def extract_ciphertext(data_payload: bytes, ciphertext_size: int) -> tuple[int, bytes]:
        seq_counter, padded_ciphertext = FrameCodec.unpack_data_frame(data_payload)
        if (
            isinstance(ciphertext_size, bool)
            or not isinstance(ciphertext_size, int)
            or not 0 <= ciphertext_size <= MAX_CIPHERTEXT_SIZE
        ):
            raise ValueError("La longitud de ciphertext excede el maximo CAN-FD.")
        expected_size = FrameCodec._padded_frame_size(FRAME_HEADER_SIZE + ciphertext_size)
        if len(data_payload) != expected_size:
            raise ValueError("La longitud del frame no corresponde al ciphertext declarado.")
        ciphertext = padded_ciphertext[:ciphertext_size]
        if any(padded_ciphertext[ciphertext_size:]):
            raise ValueError("El padding del frame de datos debe ser cero.")
        return seq_counter, ciphertext

    @staticmethod
    def pack_auth_frame(
        nonce: bytes,
        tag: bytes,
        seq_counter: int,
        ciphertext_size: int,
    ) -> bytes:
        """Empaqueta metadatos de autenticacion en un frame CAN-FD de 48 bytes."""
        if not isinstance(nonce, bytes) or not isinstance(tag, bytes):
            raise TypeError("Nonce y tag AES-GCM deben ser de tipo bytes.")
        if len(nonce) != AES_GCM_NONCE_SIZE or len(tag) != AES_GCM_TAG_SIZE:
            raise ValueError("Nonce o tag AES-GCM de longitud invalida.")
        FrameCodec._validate_sequence(seq_counter)
        if (
            isinstance(ciphertext_size, bool)
            or not isinstance(ciphertext_size, int)
            or not 0 <= ciphertext_size <= MAX_CIPHERTEXT_SIZE
        ):
            raise ValueError("La longitud de ciphertext excede el maximo CAN-FD.")
        payload = (
            bytes((AUTH_FRAME_TYPE,))
            + struct.pack(">I", seq_counter)
            + bytes((ciphertext_size,))
            + nonce
            + tag
        )
        return payload.ljust(AUTH_FRAME_SIZE, b"\x00")

    @staticmethod
    def unpack_auth_frame(auth_payload: bytes) -> tuple[bytes, bytes, int, int]:
        """Desempaqueta nonce, tag GCM y contador del frame de autenticacion."""
        if len(auth_payload) != AUTH_FRAME_SIZE or auth_payload[0] != AUTH_FRAME_TYPE:
            raise ValueError("Frame de autenticacion CAN-Secure malformado.")

        seq_counter = struct.unpack(">I", auth_payload[1:FRAME_HEADER_SIZE])[0]
        FrameCodec._validate_sequence(seq_counter)
        ciphertext_size = auth_payload[FRAME_HEADER_SIZE]
        if ciphertext_size > MAX_CIPHERTEXT_SIZE:
            raise ValueError("La longitud de ciphertext excede el maximo CAN-FD.")
        nonce = auth_payload[AUTH_NONCE_OFFSET:AUTH_TAG_OFFSET]
        tag = auth_payload[AUTH_TAG_OFFSET:AUTH_LOGICAL_SIZE]
        if any(auth_payload[AUTH_LOGICAL_SIZE:]):
            raise ValueError("El padding del frame de autenticacion debe ser cero.")
        return bytes(nonce), bytes(tag), seq_counter, ciphertext_size

    @staticmethod
    def associated_data(base_id: int, seq_counter: int) -> bytes:
        """Vincula la autenticacion al ID CAN base y al contador."""
        FrameCodec.validate_base_id(base_id)
        FrameCodec._validate_sequence(seq_counter)
        return struct.pack(">II", base_id, seq_counter)
