import time
from dataclasses import dataclass

from core.frame_codec import (AUTH_FRAME_TYPE, DATA_FRAME_TYPE, FrameCodec,)

#   Clase de errores
class FrameAssemblyError(ValueError):
    def __init__(self, message: str, base_id: int | None = None):
        super().__init__(message)
        self.base_id = base_id

#   Clase de frame (inmutable)
@dataclass(frozen=True)
class SecureFrame:
    base_id: int
    seq_counter: int
    ciphertext: bytes
    nonce: bytes
    tag: bytes

#   Clase de frame pendiente
@dataclass
class _PendingFrame:
    created_at: float
    data_payload: bytes | None = None
    auth: tuple[bytes, bytes, int] | None = None

#   Clase de ensamblado de frames
class FrameReassembler:
    def __init__(self, base_ids=None, timeout: float = 1.0, max_pending: int = 128,):
        #   Valida el timeout y el numero de frames pendientes
        if timeout <= 0:
            raise ValueError("El timeout de reensamblaje debe ser positivo.")
        if max_pending <= 0:
            raise ValueError("El limite de frames pendientes debe ser positivo.")
        #   Obtiene los base IDs validados en caso de existir
        configured_ids = None if base_ids is None else FrameCodec.validate_base_ids(base_ids)
        #   Si existen IDs base elimina los duplicados y los asigna a los principales de forma inmutable
        self.base_ids = None if configured_ids is None else frozenset(configured_ids)
        #   Asigna las IDs reservadas en caso de existir a una logica de (base_id, base_id + 1)
        self.reserved_ids = (None if self.base_ids is None else frozenset(frame_id for base_id in self.base_ids for frame_id in (base_id, base_id + 1)))
        #   Inicializa el reassembler con los valores de la clase.
        self.timeout = timeout
        self.max_pending = max_pending
        #   Crear diccionario interno de pendientes
        self._pending: dict[tuple[int, int], _PendingFrame] = {}

    #   Getter del diccionario de pendientes
    @property
    def pending_count(self) -> int:
        return len(self._pending)

    #   Eliminar frames expirados
    def expire(self, now: float | None = None) -> list[int]:
        #   Obtener tiempo actual (en caso de que now sea None u Omitido)
        current_time = time.monotonic() if now is None else now
        #   Guardar valores expirados
        expired = [
            key for key, pending in self._pending.items()
            if current_time - pending.created_at >= self.timeout
        ]
        #   Eliminar los frames expirados y regresar unicamente los Base IDs validos
        for key in expired:
            del self._pending[key]
        return [base_id for base_id, _ in expired]

    def feed(self, arbitration_id: int, payload: bytes, *, is_fd: bool = True, is_extended_id: bool = False, is_remote_frame: bool = False, is_error_frame: bool = False, now: float | None = None,) -> SecureFrame | None:
        #   Validar que el payload sea operado en bytes
        payload = bytes(payload)

        #   Valida que el frame sea estandar, de fallar guarda el mensaje e ID como un objeto de error
        if is_extended_id or is_remote_frame or is_error_frame or not is_fd:
            raise FrameAssemblyError("Se requiere un frame CAN-FD estándar.", self._guess_base_id(arbitration_id, payload))
        #   Valida que exista un payload y el tipo sea correcto
        if not payload or payload[0] not in (DATA_FRAME_TYPE, AUTH_FRAME_TYPE):
            return None


        #   Obtiene y compara el tipo del payload
        frame_type = payload[0]
        #   Si el payload actual es el de datos
        if frame_type == DATA_FRAME_TYPE:
            base_id = arbitration_id
            #   Obtener unicamente en contador de secuencia, lanzar error de ser necesario
            try:
                FrameCodec.validate_base_id(base_id)
                seq_counter, _ = FrameCodec.unpack_data_frame(payload)
            except (TypeError, ValueError) as error:
                raise FrameAssemblyError(str(error), self._guess_base_id(arbitration_id, payload),) from error
            auth = None
        #   Si el payload es de autenticacion
        else:
            base_id = arbitration_id - 1
            #   Obtener y guardar los datos de autenticacion, levatar un error de ser necesario
            try:
                FrameCodec.validate_base_id(base_id)
                nonce, tag, seq_counter, ciphertext_size = FrameCodec.unpack_auth_frame(payload)
            except (TypeError, ValueError) as error:
                raise FrameAssemblyError(str(error), self._guess_base_id(arbitration_id, payload),) from error
            auth = (nonce, tag, ciphertext_size)

        #   Validar que la base ID exista dentro del registro
        if self.base_ids is not None and base_id not in self.base_ids:
            raise FrameAssemblyError("ID base fuera de la asignacion CAN-Secure.", base_id)

        #   Usar el base ID y el contador de secuencia para determinar si el frame esta pendiente o no
        #   Sino lo esta, lo agrega a los frames pendientes con el tiempo actual
        key = (base_id, seq_counter)
        pending = self._pending.get(key)
        if pending is None:
            if len(self._pending) >= self.max_pending:
                raise FrameAssemblyError("Limite de frames CAN-Secure pendientes alcanzado.", base_id)
            current_time = time.monotonic() if now is None else now
            pending = _PendingFrame(created_at=current_time)
            self._pending[key] = pending

        #   Valida que los payload (ambos datos y autenticacion) no existan, y los asigna, si ya existen lanza un error de duplicado
        if frame_type == DATA_FRAME_TYPE:
            if pending.data_payload is not None:
                raise FrameAssemblyError("Frame de datos duplicado antes de completar el par.", base_id)
            pending.data_payload = payload
        else:
            if pending.auth is not None:
                raise FrameAssemblyError("Frame de autenticacion duplicado antes de completar el par.", base_id)
            pending.auth = auth

        if pending.data_payload is None or pending.auth is None:
            return None

        #   Elimina el payload de la lista de pendientes y obtiene sus datos de autenticacion
        del self._pending[key]
        nonce, tag, ciphertext_size = pending.auth
        #   Obtiene la trama cifrada junto con el contador de secuencia del payload de datos, los compara y regresa un frame completo en caso de exito
        try:
            data_seq, ciphertext = FrameCodec.extract_ciphertext(pending.data_payload, ciphertext_size,)
        except ValueError as error:
            raise FrameAssemblyError(str(error), base_id) from error
        if data_seq != seq_counter:
            raise FrameAssemblyError("Los contadores de los frames no coinciden.", base_id)
        return SecureFrame(base_id, seq_counter, ciphertext, nonce, tag)

    #   Funcion para obtener el base ID del par si se desconoce
    @staticmethod
    def _guess_base_id(arbitration_id: int, payload: bytes) -> int | None:
        if payload and payload[0] == AUTH_FRAME_TYPE:
            arbitration_id -= 1
        try:
            FrameCodec.validate_base_id(arbitration_id)
        except (TypeError, ValueError):
            return None
        return arbitration_id
