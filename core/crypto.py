import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEMO_KEY = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
AES_GCM_NONCE_SIZE = 12
AES_GCM_TAG_SIZE = 16

class CryptoManager:
    def __init__(self, secret_key: bytes):
        self._cipher = AESGCM(secret_key)

    def encrypt(self, plaintext: bytes, associated_data: bytes) -> tuple[bytes, bytes, bytes]:
        """Cifra con AES-GCM y devuelve nonce, ciphertext y tag por separado."""
        nonce = os.urandom(AES_GCM_NONCE_SIZE)
        ciphertext_and_tag = self._cipher.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext_and_tag[:-AES_GCM_TAG_SIZE], ciphertext_and_tag[-AES_GCM_TAG_SIZE:]

    def decrypt(self, ciphertext: bytes, nonce: bytes, tag: bytes, associated_data: bytes) -> bytes:
        """Verifica el tag GCM y descifra; InvalidTag indica fallo de autenticación."""
        if len(nonce) != AES_GCM_NONCE_SIZE or len(tag) != AES_GCM_TAG_SIZE:
            raise ValueError("Nonce o tag AES-GCM de longitud invalida.")
        return self._cipher.decrypt(nonce, ciphertext + tag, associated_data)