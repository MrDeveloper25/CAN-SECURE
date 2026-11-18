import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEMO_KEY = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
AES_GCM_NONCE_SIZE = 12
AES_GCM_TAG_SIZE = 16

class CryptoManager:
    def __init__(self, secret_key: bytes):
        self._cipher = AESGCM(secret_key)

    def update_key(self, secret_key: bytes):
        """Actualiza la clave utilizada por AES-GCM."""
        if not isinstance(secret_key, bytes):
            raise TypeError("La clave debe ser de tipo bytes.")

        if len(secret_key) not in (16, 24, 32):
            raise ValueError("La clave AES debe tener 16, 24 o 32 bytes.")

        self._cipher = AESGCM(secret_key)

    def encrypt(
        self,
        plaintext: bytes,
        associated_data: bytes,
        nonce: bytes | None = None,
    ) -> tuple[bytes, bytes, bytes]:
        """Cifra con AES-GCM; el nonce puede provenir del gestor persistente."""
        nonce = os.urandom(AES_GCM_NONCE_SIZE) if nonce is None else nonce
        if not isinstance(nonce, bytes) or len(nonce) != AES_GCM_NONCE_SIZE:
            raise ValueError("El nonce AES-GCM debe tener exactamente 12 bytes.")
        ciphertext_and_tag = self._cipher.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext_and_tag[:-AES_GCM_TAG_SIZE], ciphertext_and_tag[-AES_GCM_TAG_SIZE:]

    def decrypt(self, ciphertext: bytes, nonce: bytes, tag: bytes, associated_data: bytes) -> bytes:
        """Verifica el tag GCM y descifra; InvalidTag indica fallo de autenticación."""
        if len(nonce) != AES_GCM_NONCE_SIZE or len(tag) != AES_GCM_TAG_SIZE:
            raise ValueError("Nonce o tag AES-GCM de longitud invalida.")
        return self._cipher.decrypt(nonce, ciphertext + tag, associated_data)