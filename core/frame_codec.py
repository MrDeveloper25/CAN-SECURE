#   Importar librerias publicas
import struct

#   Constantes
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
    #   Funcion para validar el tamaño del payload, recorre los tamaños posibles (CAN_FD_DLC_LENGTHS) y si se excede el valor se lanza un error.
    #   Si todo sale bien, regresa el tamaño con el que trabaja el payload.
    @staticmethod
    def _padded_frame_size(logical_size: int) -> int:
        for size in CAN_FD_DLC_LENGTHS:
            if logical_size <= size:
                return size
        raise ValueError("El frame excede el payload maximo de CAN-FD.")

    #   Funcion para validar el base ID, metodo auxiliar que lanza un error en caso de que el base ID sea booleano, diferente a un entero o salga del rango.
    @staticmethod
    def validate_base_id(base_id: int) -> None:
        if isinstance(base_id, bool) or not isinstance(base_id, int):
            raise TypeError("El ID base debe ser un entero.")
        if not 0 <= base_id <= 0x7FE:
            raise ValueError("El ID base debe permitir un par dentro del rango CAN estándar de 11 bits.")

    #   Funcion de validacion del base ID, revisa duplicados, que los IDs sean unicos y sean validos.
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

    #   Funcion de validado de secuencias, levanta un error si el contador NO es entero o sale del rango (definido en hexadecimal).
    @staticmethod
    def _validate_sequence(seq_counter: int) -> None:
        if isinstance(seq_counter, bool) or not isinstance(seq_counter, int):
            raise TypeError("El contador de secuencia debe ser un entero.")
        if not 1 <= seq_counter <= 0xFFFFFFFF:
            raise ValueError("El contador de secuencia debe estar entre 1 y 2^32-1.")

    #   Funcion de empaquetado de datos, revisa que el tipo y longitud de ciphertext sean correctos, valida la secuencia (_validate_sequence), empaqueta el payload en bytes.
    #   El empaquetado incluye el tipo de dato, la secuencia empaquetada y el texto cifrado. Regresa el empaquetado en bytes, rellenando en 0s el espacio restante.
    @staticmethod
    def pack_data_frame(ciphertext: bytes, seq_counter: int) -> bytes:
        if not isinstance(ciphertext, bytes):
            raise TypeError("El ciphertext debe ser de tipo bytes.")
        if len(ciphertext) > MAX_CIPHERTEXT_SIZE:
            raise ValueError(f"El payload cifrado no puede superar los {MAX_CIPHERTEXT_SIZE} bytes.")
        FrameCodec._validate_sequence(seq_counter)
        payload = bytes((DATA_FRAME_TYPE,)) + struct.pack(">I", seq_counter) + ciphertext
        return payload.ljust(FrameCodec._padded_frame_size(len(payload)), b"\x00")

    #   Funcion de desempaquetado, revisa que el payload sea valido (de acuerdo a lo que regresa pack_data_frame), desempaqueta el contador de secuencia y lo valida.
    #   Regresa una tupla con el contador de secuencia y el payload por separado (seq, payload)
    @staticmethod
    def unpack_data_frame(data_payload: bytes) -> tuple[int, bytes]:
        if (len(data_payload) < FRAME_HEADER_SIZE or len(data_payload) not in CAN_FD_DLC_LENGTHS or data_payload[0] != DATA_FRAME_TYPE):
            raise ValueError("Frame de datos CAN-Secure malformado.")
        seq_counter = struct.unpack(">I", data_payload[1:FRAME_HEADER_SIZE])[0]
        FrameCodec._validate_sequence(seq_counter)
        return seq_counter, data_payload[FRAME_HEADER_SIZE:]

    #   Funcion para extraer la trama.
    @staticmethod
    def extract_ciphertext(data_payload: bytes, ciphertext_size: int) -> tuple[int, bytes]:
        #   Extraer el contador de secuencia y el texto con padding
        seq_counter, padded_ciphertext = FrameCodec.unpack_data_frame(data_payload)
        #   Validar que el tipo y rango del tamaño sean validos
        if (isinstance(ciphertext_size, bool) or not isinstance(ciphertext_size, int) or not 0 <= ciphertext_size <= MAX_CIPHERTEXT_SIZE):
            raise ValueError("La longitud de ciphertext excede el maximo CAN-FD.")
        #   Validar que el tamaño del frame sea correcto
        expected_size = FrameCodec._padded_frame_size(FRAME_HEADER_SIZE + ciphertext_size)
        if len(data_payload) != expected_size:
            raise ValueError("La longitud del frame no corresponde al ciphertext declarado.")
        #   Confirmar que el padding sean unicamente 0s
        if any(padded_ciphertext[ciphertext_size:]):
            raise ValueError("El padding del frame de datos debe ser cero.")
        #   Extraer el frame y regresar tanto el contador de secuencia como el frame.
        ciphertext = padded_ciphertext[:ciphertext_size]
        return seq_counter, ciphertext

    #   Funcion de empaquetado de payload de autenticacion 
    @staticmethod
    def pack_auth_frame(nonce: bytes, tag: bytes, seq_counter: int, ciphertext_size: int,) -> bytes:
        #   Valida el nonce y el tag, tanto en tamaños como en tipo
        if not isinstance(nonce, bytes) or not isinstance(tag, bytes):
            raise TypeError("Nonce y tag AES-GCM deben ser de tipo bytes.")
        if len(nonce) != AES_GCM_NONCE_SIZE or len(tag) != AES_GCM_TAG_SIZE:
            raise ValueError("Nonce o tag AES-GCM de longitud invalida.")
        #   Valida el contador de secuencia y el texto cifrado
        FrameCodec._validate_sequence(seq_counter)
        if (isinstance(ciphertext_size, bool) or not isinstance(ciphertext_size, int) or not 0 <= ciphertext_size <= MAX_CIPHERTEXT_SIZE):
            raise ValueError("La longitud de ciphertext excede el maximo CAN-FD.")
        #   Crea el payload con el tipo, contador de secuencia empaquetado, el tamaño del texto cifrado, nonce y tag
        payload = (bytes((AUTH_FRAME_TYPE,)) + struct.pack(">I", seq_counter) + bytes((ciphertext_size,)) + nonce + tag)
        #   Regresa el payload con un tamaño de 48 bytes, rellenando los faltantes con 0s
        return payload.ljust(AUTH_FRAME_SIZE, b"\x00")

    #   Funcion de desempaquetado del payload de autenticacion
    @staticmethod
    def unpack_auth_frame(auth_payload: bytes) -> tuple[bytes, bytes, int, int]:
        #   Validar el tamaño y tipo del payload
        if len(auth_payload) != AUTH_FRAME_SIZE or auth_payload[0] != AUTH_FRAME_TYPE:
            raise ValueError("Frame de autenticacion CAN-Secure malformado.")
        #   Desempaquetar y validar el contador de secuencia y el texto cifrado
        seq_counter = struct.unpack(">I", auth_payload[1:FRAME_HEADER_SIZE])[0]
        FrameCodec._validate_sequence(seq_counter)
        ciphertext_size = auth_payload[FRAME_HEADER_SIZE]
        if ciphertext_size > MAX_CIPHERTEXT_SIZE:
            raise ValueError("La longitud de ciphertext excede el maximo CAN-FD.")
        #   Desempaquetar el nonce y tag
        nonce = auth_payload[AUTH_NONCE_OFFSET:AUTH_TAG_OFFSET]
        tag = auth_payload[AUTH_TAG_OFFSET:AUTH_LOGICAL_SIZE]
        #   Validar que el espacio de padding contenga unicamente 0s
        if any(auth_payload[AUTH_LOGICAL_SIZE:]):
            raise ValueError("El padding del frame de autenticacion debe ser cero.")
        #   Regresar los valores desempaquetados
        return bytes(nonce), bytes(tag), seq_counter, ciphertext_size

    #   Empaquetar/vincular el ID base y el contador de secuencia.
    @staticmethod
    def associated_data(base_id: int, seq_counter: int) -> bytes:
        FrameCodec.validate_base_id(base_id)
        FrameCodec._validate_sequence(seq_counter)
        return struct.pack(">II", base_id, seq_counter)
