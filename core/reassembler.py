"""Reensamblador de tramas del esquema de frame dividido.

PROBLEMA QUE RESUELVE
---------------------
El codigo anterior asumia que el Frame 2 (auth) llegaba SIEMPRE justo despues
del Frame 1 (datos) con dos `recv()` seguidos. En un bus compartido donde un
atacante inyecta trafico, las tramas se intercalan y ese emparejamiento por
adyacencia se rompe (se emparejaba el frame de datos legitimo con la basura del
atacante, o viceversa).

SOLUCION
--------
Se bufferiza por ID base y se empareja Frame 1 (ID par) con Frame 2 (ID+1)
cuando AMBOS estan presentes, sin importar que llegue en medio. Un frame de
datos que nunca recibe su par de auth dentro de REASSEMBLY_TIMEOUT se reporta
como "huerfano" -> candidato a inyeccion no autenticada (spoofing).
"""

import time
from collections import namedtuple

from core import config

# Resultado de un emparejamiento exitoso.
AssembledFrame = namedtuple("AssembledFrame", ["base_id", "data", "auth_payload", "timestamp"])


class FrameReassembler:
    def __init__(self, timeout: float = config.REASSEMBLY_TIMEOUT):
        self.timeout = timeout
        # base_id -> (data_bytes, timestamp)
        self._pending_data = {}
        # base_id -> (auth_bytes, timestamp)
        self._pending_auth = {}

    def feed(self, arbitration_id: int, data: bytes, timestamp: float | None = None):
        """Alimenta una trama cruda. Devuelve AssembledFrame si se completo un
        par datos+auth, o None si todavia esta pendiente."""
        if timestamp is None:
            timestamp = time.time()

        if config.is_auth_id(arbitration_id):
            base = arbitration_id - config.AUTH_ID_OFFSET
            self._pending_auth[base] = (data, timestamp)
        else:
            base = arbitration_id
            self._pending_data[base] = (data, timestamp)

        if base in self._pending_data and base in self._pending_auth:
            data_bytes, ts = self._pending_data.pop(base)
            auth_bytes, _ = self._pending_auth.pop(base)
            return AssembledFrame(base, data_bytes, auth_bytes, ts)
        return None

    def collect_orphans(self, now: float | None = None):
        """Devuelve y descarta los frames de datos que esperaron su par de auth
        mas que `timeout`. Estos son inyecciones sin autenticacion (spoofing)."""
        if now is None:
            now = time.time()
        orphans = []
        for base, (data_bytes, ts) in list(self._pending_data.items()):
            if now - ts > self.timeout:
                orphans.append((base, data_bytes))
                del self._pending_data[base]
        # Frames de auth sin datos tambien son basura; se descartan.
        for base, (_, ts) in list(self._pending_auth.items()):
            if now - ts > self.timeout:
                del self._pending_auth[base]
        return orphans
