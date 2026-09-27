class KeyManager:
    def __init__(self, initial_key: bytes = b'secret_key_ecu1'):
        self.current_key = initial_key

    def get_key(self) -> bytes:
        return self.current_key

    def rotate_key(self, new_key: bytes):
        """Actualiza la clave simétrica almacenada."""
        self.current_key = new_key
        print("[KeyManager] Clave simétrica actualizada correctamente.")