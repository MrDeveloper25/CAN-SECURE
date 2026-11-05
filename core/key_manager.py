from core.crypto import DEMO_KEY

class KeyManager:
    def __init__(self, initial_key: bytes = DEMO_KEY):
        self.current_key = initial_key

    def get_key(self) -> bytes:
        return self.current_key

    def rotate_key(self, new_key: bytes):
        """Actualiza la clave simetrica almacenada."""
        self.current_key = new_key
        print("[KeyManager] Clave simetrica actualizada correctamente.")