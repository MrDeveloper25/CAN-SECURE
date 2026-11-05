from core.crypto import DEMO_KEY

class KeyManager:
    def __init__(self, initial_key: bytes = DEMO_KEY):
        self._validate_key(initial_key)
        self.current_key = initial_key
        self.crypto_managers = []

    def _validate_key(self, key: bytes):
        if not isinstance(key, bytes):
            raise TypeError("La clave debe ser de tipo bytes.")

        if len(key) not in (16, 24, 32):
            raise ValueError("La clave AES debe tener 16, 24 o 32 bytes.")

    def get_key(self) -> bytes:
        return self.current_key

    def register_crypto(self, crypto):
        """Registra un cifrador para mantenerlo sincronizado."""
        self.crypto_managers.append(crypto)

    def rotate_key(self, new_key: bytes):
        self._validate_key(new_key)
        self.current_key = new_key

        for crypto in self.crypto_managers:
            crypto.update_key(new_key)
        print("[KeyManager] Clave simetrica actualizada correctamente.")