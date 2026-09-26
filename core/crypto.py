import hmac
import hashlib

class CryptoManager:
    def __init__(self, secret_key: bytes):
        self.secret_key = secret_key

    def generate_mac(self, data: bytes) -> bytes:
        """Genera una firma HMAC-SHA256 de 32 bytes (256 bits)."""
        return hmac.new(self.secret_key, data, hashlib.sha256).digest()

    def verify_mac(self, data: bytes, mac: bytes) -> bool:
        """Compara de forma segura la firma HMAC generada contra la recibida."""
        expected_mac = self.generate_mac(data)
        return hmac.compare_digest(expected_mac, mac)