"""Primitivas de sistema de archivos portables entre Linux y Windows.

En POSIX se mantiene el comportamiento original: bloqueo con ``fcntl.flock``,
permisos 0600/0700 y ``fsync`` del directorio tras reemplazos atomicos.

En Windows no existen ``fcntl`` ni los bits de permisos POSIX (NTFS usa ACLs):
- el bloqueo se hace con ``msvcrt.locking`` sobre el primer byte del archivo;
- ``fchmod`` y la validacion de permisos privados no aplican, por lo que el
  almacen depende de las ACLs del perfil del usuario y NO se verifica;
- no se puede abrir un directorio para ``fsync``; ``os.replace`` sigue siendo atomico.
"""

import os
import stat
import time

IS_WINDOWS = os.name == "nt"

if IS_WINDOWS:
    import msvcrt
else:
    import fcntl


def lock_exclusive(fd: int) -> None:
    """Bloquea el descriptor de forma exclusiva, esperando si otro lo tiene."""
    if not IS_WINDOWS:
        fcntl.flock(fd, fcntl.LOCK_EX)
        return
    while True:
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return
        except OSError:
            time.sleep(0.005)


def unlock(fd: int) -> None:
    if not IS_WINDOWS:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return
    os.lseek(fd, 0, os.SEEK_SET)
    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)


def make_private(fd: int) -> None:
    """Aplica permisos 0600 en POSIX; en Windows no tiene equivalente directo."""
    if not IS_WINDOWS:
        os.fchmod(fd, 0o600)


def has_insecure_mode(mode: int) -> bool:
    """Indica si el modo da acceso a grupo/otros. Siempre False en Windows."""
    if IS_WINDOWS:
        return False
    return bool(stat.S_IMODE(mode) & 0o077)


def fsync_directory(path) -> None:
    """Sincroniza la entrada de directorio tras ``os.replace`` (solo POSIX)."""
    if IS_WINDOWS:
        return
    directory_fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
