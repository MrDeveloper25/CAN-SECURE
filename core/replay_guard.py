import json
import os
import stat
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path

from core.platform_compat import (
    fsync_directory,
    has_insecure_mode,
    lock_exclusive,
    make_private,
    unlock,
)

MAX_SEQUENCE = 0xFFFFFFFF


class ReplayGuard:
    def __init__(self, state_path: str | os.PathLike | None = None):
        self._lock = threading.RLock()
        self._state_path = None if state_path is None else Path(state_path).expanduser()
        self._lock_path = None if self._state_path is None else self._state_path.with_suffix(
            self._state_path.suffix + ".lock"
        )
        self.last_counters = {}
        if self._state_path is not None:
            self._prepare_state_directory()
            with self._file_lock():
                if self._state_path.exists():
                    self.last_counters = self._read_state()
                else:
                    self._write_state(self.last_counters)

    def _prepare_state_directory(self) -> None:
        parent = self._state_path.parent
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if parent.is_symlink() or not parent.is_dir():
            raise ValueError("El directorio anti-replay debe ser un directorio real.")
        mode = stat.S_IMODE(parent.stat().st_mode)
        if has_insecure_mode(mode):
            raise PermissionError(
                f"El directorio anti-replay debe tener permisos privados (actual: {mode:o})."
            )

    @contextmanager
    def _file_lock(self):
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self._lock_path, flags, 0o600)
        except OSError as error:
            raise PermissionError("No se pudo abrir de forma segura el bloqueo anti-replay.") from error
        try:
            make_private(fd)
            lock_exclusive(fd)
            try:
                yield
            finally:
                unlock(fd)
        finally:
            os.close(fd)

    def _read_state(self) -> dict[int, int]:
        if self._state_path.is_symlink():
            raise PermissionError("El archivo anti-replay no puede ser un enlace simbolico.")
        info = self._state_path.stat()
        if not stat.S_ISREG(info.st_mode) or has_insecure_mode(info.st_mode):
            raise PermissionError("El estado anti-replay debe ser un archivo regular y privado.")
        try:
            state = json.loads(self._state_path.read_bytes())
            if state["format"] != 1 or not isinstance(state["last_counters"], dict):
                raise ValueError("Formato anti-replay persistido invalido.")
            counters = {}
            for base_id, counter in state["last_counters"].items():
                if (
                    not isinstance(base_id, str)
                    or not base_id.isdecimal()
                    or not 0 <= int(base_id) <= 0x7FE
                    or isinstance(counter, bool)
                    or not isinstance(counter, int)
                    or not 1 <= counter <= MAX_SEQUENCE
                ):
                    raise ValueError("Contador anti-replay persistido invalido.")
                counters[int(base_id)] = counter
            return counters
        except (KeyError, TypeError, json.JSONDecodeError, UnicodeDecodeError) as error:
            raise ValueError("El estado anti-replay esta corrupto o incompleto.") from error

    def _write_state(self, counters: dict[int, int]) -> None:
        state = {
            "format": 1,
            "last_counters": {
                str(base_id): counter for base_id, counter in sorted(counters.items())
            },
        }
        encoded = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("ascii")
        fd, temporary_path = tempfile.mkstemp(prefix=".replay-state-", dir=self._state_path.parent)
        try:
            make_private(fd)
            with os.fdopen(fd, "wb") as state_file:
                state_file.write(encoded)
                state_file.flush()
                os.fsync(state_file.fileno())
            os.replace(temporary_path, self._state_path)
            fsync_directory(self._state_path.parent)
        finally:
            if os.path.exists(temporary_path):
                os.unlink(temporary_path)

    def is_valid_sequence(self, msg_id: int, seq_counter: int) -> bool:
        """Comprueba que el contador sea mayor sin modificar el estado."""
        if (
            isinstance(msg_id, bool)
            or not isinstance(msg_id, int)
            or not 0 <= msg_id <= 0x7FE
            or isinstance(seq_counter, bool)
            or not isinstance(seq_counter, int)
            or not 1 <= seq_counter <= MAX_SEQUENCE
        ):
            return False
        with self._lock:
            if self._state_path is not None:
                with self._file_lock():
                    self.last_counters = self._read_state()
            last_seq = self.last_counters.get(msg_id, -1)
            return seq_counter > last_seq

    def accept_sequence(self, msg_id: int, seq_counter: int) -> bool:
        """Persiste el contador despues de autenticar correctamente el mensaje."""
        if (
            isinstance(msg_id, bool)
            or not isinstance(msg_id, int)
            or not 0 <= msg_id <= 0x7FE
            or isinstance(seq_counter, bool)
            or not isinstance(seq_counter, int)
            or not 1 <= seq_counter <= MAX_SEQUENCE
        ):
            raise ValueError("ID o contador anti-replay invalido.")

        with self._lock:
            if self._state_path is None:
                if not self.is_valid_sequence(msg_id, seq_counter):
                    return False
                self.last_counters[msg_id] = seq_counter
                return True

            with self._file_lock():
                current = self._read_state()
                if seq_counter <= current.get(msg_id, -1):
                    self.last_counters = current
                    return False
                current[msg_id] = seq_counter
                self._write_state(current)
                self.last_counters = current
                return True
