import base64
import fcntl
import hashlib
import json
import os
import secrets
import stat
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path

from core.crypto import CryptoManager, DEMO_KEY
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAX_SEQUENCE = 0xFFFFFFFF
MAX_NONCE_COUNTER = 0xFFFFFFFFFFFFFFFF
STATE_FORMAT = 1


class KeyManager:
    def __init__(
        self,
        initial_key: bytes | None = None,
        state_path: str | os.PathLike | None = None,
    ):
        self._lock = threading.RLock()
        self._state_path = None if state_path is None else Path(state_path).expanduser()
        self._lock_path = None if self._state_path is None else self._state_path.with_suffix(
            self._state_path.suffix + ".lock"
        )

        if self._state_path is None:
            key = DEMO_KEY if initial_key is None else initial_key
            self._validate_key(key)
            self._key = key
            self._nonce_prefix = secrets.token_bytes(4)
            self._nonce_counter = 0
            self._used_key_ids = {self._key_id(key)}
            self._sequence_counters = {}
            return

        if initial_key is not None:
            self._validate_key(initial_key)
        self._prepare_state_directory()
        with self._file_lock():
            if self._state_path.exists():
                state = self._read_state()
                if initial_key is not None and state["key"] != initial_key:
                    raise ValueError("La clave inicial no coincide con la clave persistida.")
            else:
                key = secrets.token_bytes(32) if initial_key is None else initial_key
                state = self._new_state(key)
                self._write_state(state)
            self._set_state(state)

    @classmethod
    def persistent(cls, state_path: str | os.PathLike) -> "KeyManager":
        """Carga o crea un almacen privado de clave y contadores de envio."""
        return cls(state_path=state_path)

    @staticmethod
    def _validate_key(key: bytes) -> None:
        if not isinstance(key, bytes):
            raise TypeError("La clave debe ser de tipo bytes.")
        if len(key) not in (16, 24, 32):
            raise ValueError("La clave AES debe tener 16, 24 o 32 bytes.")

    @staticmethod
    def _key_id(key: bytes) -> str:
        return hashlib.sha256(key).hexdigest()

    def _derive_message_key(self, base_id: int) -> bytes:
        if isinstance(base_id, bool) or not isinstance(base_id, int) or not 0 <= base_id <= 0x7FE:
            raise ValueError("ID base invalido para derivar la clave del grupo.")
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"CAN-Secure key derivation v1",
            info=b"message-group/" + base_id.to_bytes(4, "big"),
        ).derive(self._key)

    @classmethod
    def _new_state(cls, key: bytes) -> dict:
        cls._validate_key(key)
        return {
            "format": STATE_FORMAT,
            "key": base64.b64encode(key).decode("ascii"),
            "nonce_prefix": base64.b64encode(secrets.token_bytes(4)).decode("ascii"),
            "nonce_counter": 0,
            "used_key_ids": [cls._key_id(key)],
            "sequence_counters": {},
        }

    def _prepare_state_directory(self) -> None:
        parent = self._state_path.parent
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if parent.is_symlink() or not parent.is_dir():
            raise ValueError("El directorio del almacen de claves debe ser un directorio real.")
        mode = stat.S_IMODE(parent.stat().st_mode)
        if mode & 0o077:
            raise PermissionError(
                f"El directorio del almacen debe tener permisos privados (actual: {mode:o})."
            )

    @contextmanager
    def _file_lock(self):
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self._lock_path, flags, 0o600)
        except OSError as error:
            raise PermissionError("No se pudo abrir de forma segura el bloqueo del almacen.") from error
        try:
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _read_state(self) -> dict:
        if self._state_path.is_symlink():
            raise PermissionError("El archivo de claves no puede ser un enlace simbolico.")
        try:
            info = self._state_path.stat()
        except FileNotFoundError:
            raise
        if not stat.S_ISREG(info.st_mode):
            raise PermissionError("El almacen de claves debe ser un archivo regular.")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise PermissionError("El almacen de claves debe ser privado (sin permisos de grupo/otros).")
        try:
            raw = self._state_path.read_bytes()
            state = json.loads(raw)
            if state["format"] != STATE_FORMAT:
                raise ValueError("Version de almacen de claves no soportada.")
            key = base64.b64decode(state["key"], validate=True)
            nonce_prefix = base64.b64decode(state["nonce_prefix"], validate=True)
            nonce_counter = state["nonce_counter"]
            used_key_ids = state["used_key_ids"]
            sequence_counters = state["sequence_counters"]
            self._validate_key(key)
            if len(nonce_prefix) != 4:
                raise ValueError("Prefijo de nonce persistido invalido.")
            if (
                isinstance(nonce_counter, bool)
                or not isinstance(nonce_counter, int)
                or not 0 <= nonce_counter <= MAX_NONCE_COUNTER
            ):
                raise ValueError("Contador de nonce persistido invalido.")
            if (
                not isinstance(used_key_ids, list)
                or self._key_id(key) not in used_key_ids
                or any(not isinstance(key_id, str) or len(key_id) != 64 for key_id in used_key_ids)
            ):
                raise ValueError("Historial de claves persistido invalido.")
            if not isinstance(sequence_counters, dict):
                raise ValueError("Contadores de envio persistidos invalidos.")
            for base_id, counter in sequence_counters.items():
                if (
                    not base_id.isdecimal()
                    or not 0 <= int(base_id) <= 0x7FE
                    or isinstance(counter, bool)
                    or not isinstance(counter, int)
                    or not 0 <= counter <= MAX_SEQUENCE
                ):
                    raise ValueError("Contador de envio persistido invalido.")
        except (KeyError, TypeError, json.JSONDecodeError, UnicodeDecodeError) as error:
            raise ValueError("El almacen de claves esta corrupto o incompleto.") from error

        return {
            "format": STATE_FORMAT,
            "key": base64.b64encode(key).decode("ascii"),
            "nonce_prefix": base64.b64encode(nonce_prefix).decode("ascii"),
            "nonce_counter": nonce_counter,
            "used_key_ids": used_key_ids,
            "sequence_counters": sequence_counters,
        }

    def _write_state(self, state: dict) -> None:
        encoded = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("ascii")
        fd, temporary_path = tempfile.mkstemp(prefix=".key-state-", dir=self._state_path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as state_file:
                state_file.write(encoded)
                state_file.flush()
                os.fsync(state_file.fileno())
            os.replace(temporary_path, self._state_path)
            directory_fd = os.open(self._state_path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temporary_path):
                os.unlink(temporary_path)

    def _set_state(self, state: dict) -> None:
        self._key = base64.b64decode(state["key"], validate=True)
        self._nonce_prefix = base64.b64decode(state["nonce_prefix"], validate=True)
        self._nonce_counter = state["nonce_counter"]
        self._used_key_ids = set(state["used_key_ids"])
        self._sequence_counters = {
            int(base_id): counter for base_id, counter in state["sequence_counters"].items()
        }

    def _export_state(self) -> dict:
        return {
            "format": STATE_FORMAT,
            "key": base64.b64encode(self._key).decode("ascii"),
            "nonce_prefix": base64.b64encode(self._nonce_prefix).decode("ascii"),
            "nonce_counter": self._nonce_counter,
            "used_key_ids": sorted(self._used_key_ids),
            "sequence_counters": {
                str(base_id): counter for base_id, counter in sorted(self._sequence_counters.items())
            },
        }

    @property
    def current_key(self) -> bytes:
        return self.get_key()

    def get_key(self) -> bytes:
        self.refresh()
        return self._key

    def refresh(self) -> None:
        """Sincroniza claves rotadas por otro proceso antes de verificar mensajes."""
        if self._state_path is None:
            return
        with self._lock, self._file_lock():
            self._set_state(self._read_state())

    def next_sequence(self, base_id: int) -> int:
        if isinstance(base_id, bool) or not isinstance(base_id, int) or not 0 <= base_id <= 0x7FE:
            raise ValueError("ID base invalido para el contador anti-replay.")
        with self._lock:
            if self._state_path is None:
                counter = self._sequence_counters.get(base_id, 0)
                if counter >= MAX_SEQUENCE:
                    raise OverflowError("El contador anti-replay de este ID se ha agotado.")
                counter += 1
                self._sequence_counters[base_id] = counter
                return counter

            with self._file_lock():
                self._set_state(self._read_state())
                counter = self._sequence_counters.get(base_id, 0)
                if counter >= MAX_SEQUENCE:
                    raise OverflowError("El contador anti-replay de este ID se ha agotado.")
                self._sequence_counters[base_id] = counter + 1
                self._write_state(self._export_state())
                return counter + 1

    def _next_nonce(self) -> bytes:
        if self._state_path is None:
            return secrets.token_bytes(12)
        if self._nonce_counter >= MAX_NONCE_COUNTER:
            raise OverflowError("El contador de nonce AES-GCM se ha agotado.")
        self._nonce_counter += 1
        return self._nonce_prefix + self._nonce_counter.to_bytes(8, "big")

    def encrypt(
        self,
        base_id: int,
        plaintext: bytes,
        associated_data: bytes,
    ) -> tuple[bytes, bytes, bytes]:
        """Reserva nonce y cifra con una clave derivada para el ID base."""
        self._derive_message_key(base_id)
        with self._lock:
            if self._state_path is None:
                nonce = self._next_nonce()
                return CryptoManager(self._derive_message_key(base_id)).encrypt(
                    plaintext,
                    associated_data,
                    nonce=nonce,
                )

            with self._file_lock():
                self._set_state(self._read_state())
                nonce = self._next_nonce()
                self._write_state(self._export_state())
                return CryptoManager(self._derive_message_key(base_id)).encrypt(
                    plaintext,
                    associated_data,
                    nonce=nonce,
                )

    def decrypt(
        self,
        base_id: int,
        ciphertext: bytes,
        nonce: bytes,
        tag: bytes,
        associated_data: bytes,
    ) -> bytes:
        """Verifica y descifra con la clave derivada para el ID base."""
        with self._lock:
            self.refresh()
            return CryptoManager(self._derive_message_key(base_id)).decrypt(
                ciphertext,
                nonce,
                tag,
                associated_data,
            )

    def rotate_key(self, new_key: bytes | None = None):
        new_key = secrets.token_bytes(32) if new_key is None else new_key
        self._validate_key(new_key)
        with self._lock:
            if self._state_path is None:
                state = self._export_state()
                return self._rotate_state(state, new_key, persist=False)

            with self._file_lock():
                state = self._read_state()
                self._set_state(state)
                return self._rotate_state(state, new_key, persist=True)

    def _rotate_state(self, state: dict, new_key: bytes, persist: bool):
        key_id = self._key_id(new_key)
        if key_id in self._used_key_ids:
            raise ValueError("No se puede reutilizar una clave AES anterior.")
        next_state = {
            "format": STATE_FORMAT,
            "key": base64.b64encode(new_key).decode("ascii"),
            "nonce_prefix": base64.b64encode(secrets.token_bytes(4)).decode("ascii"),
            "nonce_counter": 0,
            "used_key_ids": sorted(set(state["used_key_ids"]) | {key_id}),
            "sequence_counters": state["sequence_counters"],
        }
        if persist:
            self._write_state(next_state)
        self._set_state(next_state)
        print("[KeyManager] Clave simetrica actualizada correctamente.")
